use std::collections::{HashMap, HashSet, VecDeque};
use crate::node::{Node, Mode, NodeSignal, SignalType};
use crate::scenarios;
use crate::persistence::{NetworkLogger, SignalContent, SignalEntry};
use crate::config::{Config};
use std::sync::Arc;


#[derive(Debug, Clone)]
pub struct Link {
    pub from: usize,
    pub to: usize,
    pub active: bool,
    pub virtual_link: bool,
}


// ДАННЫЕ О ТОПОЛОГИИ, которые хранит каждый узел
#[derive(Clone, Debug)]
pub struct NodeSnapshot {
    pub node_id: u32,
    pub neighbors: Vec<u32>,
    pub timestamp: u64,       // tick, когда получено — для инвалидации устаревших данных
    pub confidence: f32,      // 1.0 = прямой сосед, <1.0 = через ретрансляцию
}

#[derive(Clone, Debug)]
pub struct TopologyMap {
    pub snapshots: HashMap<u32, NodeSnapshot>,   // node_id → его связи
    pub last_updated: u64,
}

impl TopologyMap {
    pub fn new() -> Self {
        Self {
            snapshots: HashMap::new(),
            last_updated: 0,
        }
    }

    // Обновление снепшота, если данные новее
    pub fn merge(&mut self, snapshot: NodeSnapshot, current_tick: u64) {
        let should_update = match self.snapshots.get(&snapshot.node_id) {
            None => true,
            Some(existing) => snapshot.timestamp > existing.timestamp,
        };
        if should_update {
            self.snapshots.insert(snapshot.node_id, snapshot);
            self.last_updated = current_tick;
        }
    }

    pub fn find_path(&self, from: u32, to: u32, excluded: &HashSet<u32>) -> Option<Vec<u32>> {
        // BFS по известной карте
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(vec![from]);
        visited.insert(from);

        while let Some(path) = queue.pop_front() {
            let current = *path.last().unwrap();
            if current == to {
                return Some(path);
            }
            if let Some(snap) = self.snapshots.get(&current) {
                for &neighbor in &snap.neighbors {
                    if excluded.contains(&neighbor) {
                        continue;
                    }
                    if !visited.contains(&neighbor) {
                        visited.insert(neighbor);
                        let mut new_path = path.clone();
                        new_path.push(neighbor);
                        queue.push_back(new_path);
                    }
                }
            }
        }
        None
    }

    // Обнаружить узлы, которые молчат дольше порога
    pub fn detect_stale_nodes(&self, current_tick: u64, ttl: u64) -> Vec<u32> {
        self.snapshots
            .iter()
            .filter(|(_, snap)| current_tick.saturating_sub(snap.timestamp) > ttl)
            .map(|(id, _)| *id)
            .collect()
    }
}

pub struct Network {
    pub nodes: Vec<Node>,
    pub links: Vec<Link>,
    pub tick: u64,
    pub config: Arc<Config>,
    pub max_ticks: u64,
    pub finished: bool,
    pub active_effects: Vec<scenarios::ActiveEffect>,
    pub recent_lifecycle: VecDeque<crate::persistence::LifecycleEntry>,
    pub partitioned_nodes: HashSet<u32>, // id узлов, физически отрезанных от сети (для сценария)
    pub recovered_at_tick: HashMap<u32, u64>,
}

const RECENT_LIFECYCLE_CAPACITY: usize = 200;

impl Network {
    pub fn new(nodes: Vec<Node>, links: Vec<Link>, tick: u64, config: Arc<Config>, max_ticks: u64, finished: bool) -> Self {
        Self {
            nodes,
            links,
            tick,
            config,
            max_ticks,
            finished,
            active_effects: vec![],
            recent_lifecycle: VecDeque::new(),
            partitioned_nodes: HashSet::new(),
            recovered_at_tick: HashMap::new(),
        }
    }

    fn log_signal_delivery(&self, logger: &mut NetworkLogger, signal: &NodeSignal, receiver_idx: usize) {
        let receiver_threat_level = self.nodes[receiver_idx].state.last_threat_score;
        let content = SignalContent {
            mode: format!("{:?}", signal.mode),
            load: signal.load,
            active_connections: signal.active_connections,
            failed_auth_count: signal.failed_auth_count,
            ai_state_reason: signal.ai_state_reason.clone(),
            signal_threat_score: signal.threat_score,
        };
        let entry = SignalEntry::now(
            self.tick,
            signal.source_id,
            self.nodes[receiver_idx].id,
            format!("{:?}", signal.signal_type),
            content,
            receiver_threat_level,
        );
        logger.signals.push(entry, self.tick);
    }

    pub fn build_links(topology: &Vec<(u32, Vec<u32>)>) -> Vec<Link> {
        let mut links = vec![];

        for (from, neighbors) in topology {
            for to in neighbors {
                links.push(Link {
                    from: (*from as usize) - 1,
                    to: (*to as usize) - 1,
                    active: true,
                    virtual_link: false,
                });
            }
        }
        links
    }

    pub fn apply_scenario(&mut self, scenario: scenarios::AttackScenario) {
        if let Some(active) = scenarios::ScenarioEngine::apply(self, &scenario) {
            self.active_effects.push(active);
        }
    }
    
    fn sync_isolation_links(&mut self) {
        for link in &mut self.links {
            let from_id = self.nodes[link.from].id;
            let to_id   = self.nodes[link.to].id;

            let from_cut = self.nodes[link.from].state.mode == Mode::Isolated || self.partitioned_nodes.contains(&from_id);
            let to_cut = self.nodes[link.to].state.mode == Mode::Isolated || self.partitioned_nodes.contains(&to_id);

            link.active = !from_cut && !to_cut;
        }
    }

    fn refresh_recovery_markers(&mut self, previously_cut: &HashSet<u32>) {
        for node in &self.nodes {
            let still_cut = node.state.mode == Mode::Isolated || self.partitioned_nodes.contains(&node.id);
            if !still_cut && previously_cut.contains(&node.id) {
                tracing::info!(
                    "🩹 Node {} recovery marker set at tick {} (heal_partitions grace period starts now)",
                    node.id, self.tick
                );
                self.recovered_at_tick.insert(node.id, self.tick);
            }
        }
    }

    fn currently_cut_node_ids(&self) -> HashSet<u32> {
        self.nodes
            .iter()
            .filter(|n| n.state.mode == Mode::Isolated || self.partitioned_nodes.contains(&n.id))
            .map(|n| n.id)
            .collect()
    }

    fn tick_reconnect(&mut self, logger: &mut NetworkLogger) {
        let current_tick = self.tick;

        // 1. ReconnectRequest от всех Reconnecting-узлов
        let requests: Vec<(usize, Vec<NodeSignal>)> = self.nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.state.mode == Mode::Reconnecting)
            .map(|(i, n)| (i, n.generate_reconnect_requests(current_tick)))
            .collect();

        // 2. Доставка запросы соседям и сборка Ack
        let mut acks: Vec<(usize, NodeSignal)> = vec![]; // (адресат-idx, ack)

        for (requester_idx, signals) in &requests {
            for signal in signals {
                let Some(target_id) = signal.target_id else { continue };
                let Some(target_idx) = self.nodes.iter().position(|n| n.id == target_id) else { continue };

                self.log_signal_delivery(logger, signal, target_idx);

                // Сосед решает — принять или нет
                if let Some(ack) = self.nodes[target_idx].handle_reconnect_request(signal, current_tick) {
                    tracing::info!("Node {} → ReconnectAck → Node {}", target_id, self.nodes[*requester_idx].id);
                    acks.push((*requester_idx, ack));
                }
            }
        }

        // 3. Ack обратно запрашивающему узлу
        let mut completed: Vec<usize> = vec![];

        for (requester_idx, ack) in acks {
            self.log_signal_delivery(logger, &ack, requester_idx);

            let quorum_reached = self.nodes[requester_idx].handle_reconnect_ack(&ack);
            if quorum_reached {
                completed.push(requester_idx);
            }
        }

        for &idx in &completed {
            self.nodes[idx].complete_reconnect(current_tick);
            tracing::info!("🔗 Node {} links restored", self.nodes[idx].id);
        }

        let uncompleted: Vec<usize> = requests.iter().map(|(idx, _)| *idx)
            .filter(|idx| !completed.contains(idx)).collect();

        for idx in uncompleted {
            self.nodes[idx].tick_failed_reconnect(current_tick);
        }
    }


    pub fn tick_topology_flood(&mut self) {
        let current_tick = self.tick;

        // 1. Каждый узел генерирует свой LSA
        let lsa_batch: Vec<(usize, NodeSnapshot)> = self.nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.state.mode != Mode::Isolated)
            .map(|(i, node)| {
                let snap = node.broadcast_lsa(current_tick, &self.links, &self.nodes);
                (i, snap)
            })
            .collect();

        // 2. Рассылка LSA по активным рёбрам (flooding)
        let mut delivery_queue: Vec<(usize, NodeSnapshot)> = vec![];

        for (sender_idx, snap) in &lsa_batch {
            // Все соседи отправителя получают его LSA
            for link in &self.links {
                if link.active && link.from == *sender_idx {
                    delivery_queue.push((link.to, snap.clone()));
                }
            }
        }

        // 3. Узлы принимают LSA для ретрансляции
        let mut relay_queue: Vec<(usize, NodeSnapshot)> = vec![];

        for (receiver_idx, snap) in delivery_queue {
            if let Some(relayed) = self.nodes[receiver_idx].receive_lsa(snap, current_tick) {
                // Нужна ретрансляция — отправим всем соседям получателя
                for link in &self.links {
                    if link.active && link.from == receiver_idx {
                        relay_queue.push((link.to, relayed.clone()));
                    }
                }
            }
        }

        // 4. Ретрансляция
        for (receiver_idx, snap) in relay_queue {
            self.nodes[receiver_idx].receive_lsa(snap, current_tick);
        }
    }

    // Обнаруживает узлы, потерявшие соседей, и прогоняет протокол виртуального моста
    pub fn heal_partitions(&mut self, logger: &mut NetworkLogger) {
        let current_tick = self.tick;

        let recovery_grace_ticks = self.config.security.node_stale_ttl.max(1);
        let mut excluded_bridges = self.partitioned_nodes.clone();
        let mut cannot_self_initiate = self.partitioned_nodes.clone();

        for node in &self.nodes {
            if matches!(node.state.mode, Mode::Isolated | Mode::Reconnecting) {
                excluded_bridges.insert(node.id);
                cannot_self_initiate.insert(node.id);
                continue;
            }

            let last_recovery = self.recovered_at_tick.get(&node.id).copied();
            let ticks_since_recovery = match last_recovery {
                Some(recovered_tick) => current_tick.saturating_sub(recovered_tick),
                None => u64::MAX,
            };

            if ticks_since_recovery < recovery_grace_ticks {
                excluded_bridges.insert(node.id);
            }
        }

        let mut outgoing: Vec<(usize, Vec<NodeSignal>)> = Vec::new();

        for (idx, node) in self.nodes.iter_mut().enumerate() {
            if cannot_self_initiate.contains(&node.id) {
                continue;
            }

            let signals = node.initiate_virtual_bridges(current_tick, &excluded_bridges);
            if !signals.is_empty() {
                outgoing.push((idx, signals));
            }
        }

        let mut acks: Vec<(usize, NodeSignal)> = Vec::new();

        for (sender_idx, signals) in outgoing {
            for signal in signals {
                let Some(target_id) = signal.target_id else { continue };
                let Some(target_idx) = self.nodes.iter().position(|n| n.id == target_id) else {
                    continue;
                };

                self.log_signal_delivery(logger, &signal, target_idx);
                let response = self.nodes[target_idx].handle_virtual_bridge_request(&signal, current_tick);
                self.log_signal_delivery(logger, &response, sender_idx);
                acks.push((sender_idx, response));
            }
        }

        let mut newly_confirmed: HashSet<(u32, u32)> = HashSet::new();

        for (sender_idx, response) in acks {
            let sender_id = self.nodes[sender_idx].id;
            let confirmed_locally = self.nodes[sender_idx].handle_virtual_bridge_response(&response);

            if confirmed_locally && response.signal_type == SignalType::VirtualBridgeAck {
                let pair = normalize_pair(sender_id, response.source_id);
                newly_confirmed.insert(pair);
            }
        }

        if !newly_confirmed.is_empty() {
            let id_to_index = |id: u32| self.nodes.iter().position(|n| n.id == id);
            let new_links = Node::build_confirmed_links(&newly_confirmed, id_to_index);

            for link in new_links {
                let (from_id, to_id) = (self.nodes[link.from].id, self.nodes[link.to].id);
                tracing::info!("🌉✅ Virtual bridge established: Node {} <-> Node {}", from_id, to_id);
                self.links.push(link);
            }

            for &(a, b) in &newly_confirmed {
                if let Some(idx) = self.nodes.iter().position(|n| n.id == a) {
                    self.nodes[idx].virtual_bridge_attempts.remove(&b);
                }
                if let Some(idx) = self.nodes.iter().position(|n| n.id == b) {
                    self.nodes[idx].virtual_bridge_attempts.remove(&a);
                }
            }
        }
    }

    fn cleanup_redundant_virtual_bridges(&mut self) {
        let mut redundant_pairs = std::collections::HashSet::new();
        
        // Собираем все текущие виртуальные мосты
        let virtual_edges: Vec<(usize, usize)> = self.links.iter()
            .filter(|l| l.virtual_link && l.active)
            .map(|l| (l.from, l.to))
            .collect();
            
        for (u, v) in virtual_edges {
            // Ищем ВСЕХ изначальных физических соседей (и активных, и упавших)
            let u_all_physical: std::collections::HashSet<usize> = self.links.iter()
                .filter(|l| !l.virtual_link && l.from == u)
                .map(|l| l.to)
                .collect();
                
            let v_all_physical: std::collections::HashSet<usize> = self.links.iter()
                .filter(|l| !l.virtual_link && l.from == v)
                .map(|l| l.to)
                .collect();
                
            // Находим общих физических соседей (посредников)
            let common_physical = u_all_physical.intersection(&v_all_physical);
            
            let mut all_common_active = true;
            let mut has_common = false;
            
            for &w in common_physical {
                has_common = true;
                // Проверяем, находится ли этот конкретный посредник в отключке
                let w_is_cut = matches!(self.nodes[w].state.mode, Mode::Isolated | Mode::Reconnecting) 
                    || self.partitioned_nodes.contains(&self.nodes[w].id);
                    
                if w_is_cut {
                    // Если хотя бы один посредник (например, Узел №2) всё ещё лежит, мост удалять рано!
                    all_common_active = false;
                    break;
                }
            }
            
            // Если общие соседи есть, и НИ ОДИН из них не лежит — выпавший узел вернулся. Мост можно сносить.
            if has_common && all_common_active {
                redundant_pairs.insert((u, v));
                redundant_pairs.insert((v, u));
            }
        }
        
        // Удаляем избыточные мосты из топологии
        if !redundant_pairs.is_empty() {
            self.links.retain(|l| {
                if l.virtual_link && redundant_pairs.contains(&(l.from, l.to)) {
                    tracing::info!("🔗✂ Removing redundant virtual bridge between Node {} and Node {}", self.nodes[l.from].id, self.nodes[l.to].id);
                    false
                } else {
                    true
                }
            });
        }
    }

    pub fn tick(&mut self, logger: &mut NetworkLogger) {
        if self.finished {
            return;
        }

        self.tick += 1;
        tracing::info!("--- NETWORK TICK {} ---", self.tick);

        // Широковещательные сигналы состояния
        let broadcast_signals: Vec<NodeSignal> = self
            .nodes
            .iter()
            .map(|n| n.generate_broadcast_signal(self.tick))
            .collect();

        for link in &self.links {
            if !link.active { continue; }
            let signal = broadcast_signals[link.from].clone();
            self.log_signal_delivery(logger, &signal, link.to);
            self.nodes[link.to].receive_signal(signal, self.tick);
        }

        // Направленные сигналы подозрения
        let peer_signals: Vec<(u32, Vec<NodeSignal>)> = self
            .nodes
            .iter_mut()
            .map(|n| (n.id, n.generate_peer_suspicion_signals(self.tick)))
            .collect();

        for (sender_id, signals) in peer_signals {
            for signal in signals {
                if let Some(target_id) = signal.target_id {
                    let sender_idx = self.nodes.iter().position(|n| n.id == sender_id).unwrap();
                    let target_idx = self.nodes.iter().position(|n| n.id == target_id).unwrap();
                    let link_exists = self.links.iter()
                        .any(|l| l.active && l.from == sender_idx && l.to == target_idx);
                    if link_exists {
                        tracing::info!("📡 Node {} → PeerSuspicion → Node {} (threat: {:.2})",
                            sender_id, target_id, signal.threat_score);
                        self.log_signal_delivery(logger, &signal, target_idx);
                        self.nodes[target_idx].receive_signal(signal, self.tick);
                    }
                }
            }
        }

        let all_neighbors: Vec<Vec<u32>> = self.nodes.iter().map(|node|{node.current_neighbors(&self.links, &self.nodes)}).collect();

        for (node, neighbor_ids) in self.nodes.iter_mut().zip(all_neighbors) {
            node.neighbor_ids = neighbor_ids;
        }

        // Тик узлов
        for node in &mut self.nodes {
            node.tick(self.tick);
        }

        for node in &mut self.nodes {
            for entry in node.pending_lifecycle.drain(..) {
                self.recent_lifecycle.push_back(entry.clone());
                logger.lifecycle.push(entry, self.tick);
            }
            for entry in node.pending_ai_decisions.drain(..) {
                logger.ai_decisions.push(entry, self.tick);
            }
        }
        while self.recent_lifecycle.len() > RECENT_LIFECYCLE_CAPACITY {
            self.recent_lifecycle.pop_front();
        }

        let current_tick = self.tick;
        let advisory_signals: Vec<(usize, Option<NodeSignal>)> = self.nodes
            .iter_mut()
            .enumerate()
            .map(|(i, node)| (i, node.take_load_advisory_signal(current_tick)))
            .collect();

        for (sender_idx, maybe_signal) in advisory_signals {
            let Some(signal) = maybe_signal else { continue };
            let label = match signal.signal_type {
                crate::node::SignalType::LoadReduced       => "LoadReduced",
                crate::node::SignalType::LoadBoosted       => "LoadBoosted",
                crate::node::SignalType::Isolation => "Isolation",
                _ => "LoadAdvisory",
            };
            for link in &self.links {
                if link.active && link.from == sender_idx {
                    tracing::info!(
                        "📣 Node {} → {} → Node {} (load now: {})",
                        self.nodes[sender_idx].id, label,
                        self.nodes[link.to].id, signal.load
                    );
                    self.log_signal_delivery(logger, &signal, link.to);
                    self.nodes[link.to].receive_signal(signal.clone(), current_tick);
                }
            }
        }

        self.tick_reconnect(logger);

        for node in &mut self.nodes {
            for entry in node.pending_lifecycle.drain(..) {
                self.recent_lifecycle.push_back(entry.clone());
                logger.lifecycle.push(entry, self.tick);
            }
        }
        while self.recent_lifecycle.len() > RECENT_LIFECYCLE_CAPACITY {
            self.recent_lifecycle.pop_front();
        }

        let cut_before_effects = self.currently_cut_node_ids();
        self.sync_isolation_links();

        let active_effects = std::mem::take(&mut self.active_effects);
        self.active_effects = scenarios::ScenarioEngine::advance_active_effects(self, active_effects);

        self.sync_isolation_links();
        self.refresh_recovery_markers(&cut_before_effects);
        self.cleanup_redundant_virtual_bridges();
        self.tick_topology_flood();
        self.heal_partitions(logger);

        logger.flush_all(self.tick);

        if self.tick >= self.max_ticks {
            self.finished = true;
            tracing::info!("Симуляция закончена на тике: {}", self.tick);
        }
    }
}

fn normalize_pair(a: u32, b: u32) -> (u32, u32) {
    if a < b { (a, b) } else { (b, a) }
}