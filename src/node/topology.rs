use super::{Node, Mode, NodeSignal, NeighborHistory, SignalType, VirtualBridgeAttempt};
use crate::proposal::{Proposal, ProposalAction};
use crate::network::{Link, NodeSnapshot};
use std::collections::{HashSet,};

const MIN_SNAPSHOT_CONFIDENCE: f32 = 0.3;

impl Node {
    pub fn broadcast_lsa<'a>(&self, current_tick: u64, links: &[Link], nodes: &'a [Node]) -> NodeSnapshot {
        NodeSnapshot {
            node_id: self.id,
            neighbors: self.current_neighbors(links, nodes),
            timestamp: current_tick,
            confidence: 1.0,
        }
    }

    pub fn receive_lsa(&mut self, snap: NodeSnapshot, current_tick: u64) -> Option<NodeSnapshot> {
        let already_known = self.topology_map
            .snapshots
            .get(&snap.node_id)
            .map(|existing| existing.timestamp >= snap.timestamp)
            .unwrap_or(false);

        if already_known {
            return None;
        }

        let relayed = NodeSnapshot {
            confidence: (snap.confidence * 0.9).max(0.1),
            ..snap.clone()
        };

        self.topology_map.merge(relayed.clone(), current_tick);
        Some(relayed)
    }

    pub fn current_neighbors<'a>(&self, links: &[Link], nodes: &'a [Node]) -> Vec<u32> {
        links.iter()
            .filter(|l| l.active && l.from == (self.id as usize - 1))
            .map(|l| nodes[l.to].id)
            .collect()
    }

    pub fn generate_broadcast_signal(&self, tick: u64) -> NodeSignal {
        let nd_load = self.config.node_defaults.load as f32;
        let signal_type = match self.state.mode {
            Mode::Normal => SignalType::Normal,
            Mode::Isolated => SignalType::Isolation,
            Mode::Throttled => {
                if self.state.load as f32 > nd_load {SignalType::LoadReduced} 
                else {SignalType::Normal}
            }
            Mode::Boosted => SignalType::LoadBoosted,
            Mode::Degraded => SignalType::Alert,
            Mode::Reconnecting => SignalType::ReconnectRequest,
        };

        NodeSignal {
            source_id: self.id,
            target_id: None,  // широковещательный — не адресован конкретно
            mode: self.state.mode,
            load: self.state.load,
            active_connections: self.state.active_connections,
            failed_auth_count: self.state.failed_auth_count,
            threat_score: self.state.last_threat_score,
            ai_state_reason: self.state.ai_state_reason.clone(),
            signal_type,
            timestamp: tick,
        }
    }

    // Направленные сигналы подозрения на каждого подозрительного соседа
    pub fn generate_peer_suspicion_signals(&mut self, tick: u64) -> Vec<NodeSignal> {
        let mut suspicions = Vec::new();
        
        let id = self.id;
        let ai = &mut self.ai;
        let config = &self.config;
        let history_map = &self.neighbor_history;
        let all_signals = &self.neighbor_signals;
        
        for s in all_signals.values().flatten() {
            if tick.saturating_sub(s.timestamp) > self.config.security.stale_ttl {
                continue;
            }
            if s.source_id == id || s.target_id == Some(id) {
                continue;
            }

            let empty_history = NeighborHistory::default();
            let history = history_map.get(&s.source_id).unwrap_or(&empty_history);

            let threat = Self::assess_neighbor_threat(ai, s, config, tick, history, all_signals);

            if threat >= self.config.security.threat_score_isolation && s.mode != Mode::Isolated {
                suspicions.push(NodeSignal {
                    source_id: id,
                    target_id: Some(s.source_id),
                    mode: self.state.mode,
                    load: self.state.load,
                    active_connections: self.state.active_connections,
                    failed_auth_count: self.state.failed_auth_count,
                    threat_score: threat,
                    ai_state_reason: self.state.ai_state_reason.clone(),
                    signal_type: SignalType::PeerSuspicion,
                    timestamp: tick,
                });
            }
        }

        suspicions
    }

    pub fn take_load_advisory_signal(&mut self, tick: u64) -> Option<NodeSignal> {
        let fact_signal = self.state.pending_load_signal.take()?;
        // Преобрзование: факт → призыв к действию
        let advisory_type = match fact_signal {
            SignalType::LoadReduced => SignalType::ReduceLoad,
            SignalType::LoadBoosted => SignalType::BoostLoad,
            other => other,
        };
        Some(NodeSignal {
            source_id: self.id,
            target_id: None, // широковещательный
            mode: self.state.mode,
            load: self.state.load,
            active_connections: self.state.active_connections,
            failed_auth_count: self.state.failed_auth_count,
            ai_state_reason: self.state.ai_state_reason.clone(),
            threat_score: self.state.last_threat_score,
            signal_type: advisory_type,
            timestamp: tick,
        })
    }

    // Фильтрует входящие сигналы и возвращает forced proposal, если нужно действовать в обход ИИ
    pub fn process_incoming_signals(&self, current_tick: u64) -> Option<Proposal> {
        let voting_peers: HashSet<u32> = self.neighbor_signals.values().flatten()
            .filter(|s| {
                s.signal_type == SignalType::PeerSuspicion
                && s.target_id == Some(self.id)
                && s.timestamp == current_tick  // только свежие голоса
            })
            .map(|s| s.source_id)
            .collect();

        let suspicion_count = voting_peers.len();
        let neighbor_count = self.neighbor_ids.len();
        
        let threshold = ((neighbor_count * 2 + 2) / 3).max(self.config.security.peer_suspicion_threshold); // порог в ⅔

        if neighbor_count > 0 && suspicion_count >= threshold {
            tracing::info!("⚠ Node {} forced isolation: {}/{} peers voted (threshold {})", self.id, suspicion_count, neighbor_count, threshold);
            return Some(Proposal {
                action: ProposalAction::EnterIsolation,
                threat_score: 1.0,
                predicted_state: "peer_consensus_isolation".into(),
                event_reason: "Multiple neighbors flagged this node as compromised".into(),
                confidence: 1.0
            });
        }
        None
    }

    pub fn receive_signal(&mut self, signal: NodeSignal, current_tick: u64) {
        if current_tick.saturating_sub(signal.timestamp) > self.config.security.stale_ttl {
            return;
        }

        if !self.neighbor_ids.contains(&signal.source_id) && !self.neighbor_history.contains_key(&signal.source_id) {
            tracing::warn!("Node {} dropped signal from unknown source {}", self.id, signal.source_id);
            return;
        }

        let history = self.neighbor_history.entry(signal.source_id).or_default();
        let mode_changed = history.last_signal.as_ref().map_or(true, |p| p.mode != signal.mode);
        if mode_changed {
            history.mode_entered_tick = current_tick;
            if signal.mode == Mode::Isolated {
                history.times_isolated += 1;
            }
        }

        history.recent_timestamps.push_back(current_tick);
        if history.recent_timestamps.len() > self.config.security.max_len_neighbor_signals {
            history.recent_timestamps.pop_front();
        }
        history.last_signal = Some(signal.clone());

        let bucket = self.neighbor_signals.entry(signal.source_id).or_default();
        bucket.push_back(signal);
        if bucket.len() > self.config.security.max_count_signals_from_neighbor {
            bucket.pop_front();
        }
    }

    pub fn find_virtual_bridge_candidates(&self, stale_ids: &[u32], excluded_bridges: &HashSet<u32>,) -> Vec<(u32, u32)> {
        let mut candidates = Vec::new();

        for &fallen_id in stale_ids {
            let Some(fallen_snapshot) = self.topology_map.snapshots.get(&fallen_id) else {
                continue;
            };

            if fallen_snapshot.confidence < MIN_SNAPSHOT_CONFIDENCE {
                continue;
            }
            
            let was_direct_neighbor = fallen_snapshot.neighbors.contains(&self.id);

            if !was_direct_neighbor {
                continue;
            }

            for &candidate_id in &fallen_snapshot.neighbors {
                if candidate_id == self.id {
                    continue;
                }
                if excluded_bridges.contains(&candidate_id) {
                    continue; // Кандидат тоже мертв/изолирован — к нему не строим
                }
                if self.neighbor_ids.contains(&candidate_id) {
                    continue; // Уже есть физический линк
                }
                if self.virtual_bridge_attempts
                    .get(&candidate_id)
                    .map(|a| a.initiated_by_us)
                    .unwrap_or(false)
                {
                    continue;
                }

                // Проверка, существует ли альтернативный физический маршрут
                if self
                    .topology_map
                    .find_path(self.id, candidate_id, excluded_bridges)
                    .is_none()
                {
                    continue;
                }

                candidates.push((candidate_id, fallen_id));
            }
        }

        candidates
    }

    pub fn initiate_virtual_bridges(&mut self, current_tick: u64, excluded_bridges: &HashSet<u32>,) -> Vec<NodeSignal> {
        let stale_ids = self
            .topology_map
            .detect_stale_nodes(current_tick, self.config.security.node_stale_ttl);

        if stale_ids.is_empty() {
            return vec![];
        }

        let candidates = self.find_virtual_bridge_candidates(&stale_ids, excluded_bridges);
        let mut outgoing = Vec::new();

        for (bridge_to, via_fallen_node) in candidates {
            self.virtual_bridge_attempts.insert(
                bridge_to,
                VirtualBridgeAttempt {
                    bridge_to,
                    via_fallen_node,
                    started_at_tick: current_tick,
                    attempts: 1,
                    initiated_by_us: true,
                },
            );

            tracing::info!("Node {} initiating virtual bridge to Node {} (was connected via fallen Node {})", self.id, bridge_to, via_fallen_node);

            outgoing.push(NodeSignal {
                source_id: self.id,
                target_id: Some(bridge_to),
                mode: self.state.mode,
                load: self.state.load,
                active_connections: self.state.active_connections,
                failed_auth_count: self.state.failed_auth_count,
                threat_score: self.state.last_threat_score,
                ai_state_reason: self.state.ai_state_reason.clone(),
                signal_type: SignalType::VirtualBridgeRequest,
                timestamp: current_tick,
            });
        }

        outgoing
    }

    /// Шаг 3: получатель запроса решает, принять ли мост
    pub fn handle_virtual_bridge_request(&mut self, request: &NodeSignal, current_tick: u64,) -> NodeSignal {
        let sec = &self.config.security;

        let requester_untrusted = request.threat_score > sec.threat_score_isolation || request.mode == Mode::Isolated
            || matches!(request.ai_state_reason.as_str(), "malware_detected" | "auth_bruteforce_detected" | "integrity_violation");

        // Получатель тоже не должен быть скомпрометирован
        let self_untrusted = self.state.mode == Mode::Isolated
            || matches!(
                self.state.ai_state_reason.as_str(),
                "malware_detected" | "auth_bruteforce_detected" | "integrity_violation"
            );

        let accepted = !requester_untrusted && !self_untrusted;

        if accepted {
            self.virtual_bridge_attempts.insert(
                request.source_id,
                VirtualBridgeAttempt {
                    bridge_to: request.source_id,
                    via_fallen_node: 0, // получатель не обязан знать посредника — тут не критично
                    started_at_tick: current_tick,
                    attempts: 1,
                    initiated_by_us: false,
                },
            );
            tracing::info!(
                "Node {} accepted virtual bridge from Node {}",
                self.id, request.source_id
            );
        } else {
            tracing::warn!(
                "Node {} REJECTED virtual bridge from Node {} (requester_untrusted={}, self_untrusted={})",
                self.id, request.source_id, requester_untrusted, self_untrusted
            );
        }

        NodeSignal {
            source_id: self.id,
            target_id: Some(request.source_id),
            mode: self.state.mode,
            load: self.state.load,
            active_connections: self.state.active_connections,
            failed_auth_count: self.state.failed_auth_count,
            threat_score: self.state.last_threat_score,
            ai_state_reason: self.state.ai_state_reason.clone(),
            signal_type: if accepted {
                SignalType::VirtualBridgeAck
            } else {
                SignalType::VirtualBridgeReject
            },
            timestamp: current_tick,
        }
    }

    pub fn handle_virtual_bridge_response(&mut self, response: &NodeSignal) -> bool {
        match response.signal_type {
            SignalType::VirtualBridgeAck => {
                if let Some(attempt) = self.virtual_bridge_attempts.get(&response.source_id) {
                    tracing::info!(
                        "Node {} received Ack from Node {} — bridge confirmed on this side",
                        self.id, attempt.bridge_to
                    );
                }
                true
            }
            SignalType::VirtualBridgeReject => {
                tracing::warn!("Node {} bridge to Node {} rejected — abandoning attempt", self.id, response.source_id);
                self.virtual_bridge_attempts.remove(&response.source_id);
                false
            }
            _ => false,
        }
    }

    pub fn build_confirmed_links(confirmed_pairs: &HashSet<(u32, u32)>, id_to_index: impl Fn(u32) -> Option<usize>,) -> Vec<Link> {
        let mut links = Vec::new();
        for &(a, b) in confirmed_pairs {
            let (Some(ia), Some(ib)) = (id_to_index(a), id_to_index(b)) else {
                continue;
            };
            // Двусторонний канал — два Link, как и в исходной топологии (from/to оба направления)
            links.push(Link { from: ia, to: ib, active: true, virtual_link: true });
            links.push(Link { from: ib, to: ia, active: true, virtual_link: true });
        }
        links
    }
}