use std::collections::HashMap;
use rand::seq::SliceRandom;
use rand::rng;
use crate::network::Network;
use crate::node::{Mode, SignalType};


// Цель сценария
#[derive(Debug, Clone)]
pub enum ScenarioTarget {
    ById(u32),
    Random { count: usize },
    NeighborsOf(u32),
    Ids(Vec<u32>), // Явный список id
    All, // Вся сеть целиком
}

impl ScenarioTarget {
    // Резолвит цель в список индексов в `network.nodes` (не id)
    fn resolve(&self, network: &Network) -> Vec<usize> {
        match self {
            ScenarioTarget::ById(id) => network
                .nodes
                .iter()
                .position(|n| n.id == *id)
                .into_iter()
                .collect(),

            ScenarioTarget::Ids(ids) => ids
                .iter()
                .filter_map(|id| network.nodes.iter().position(|n| n.id == *id))
                .collect(),

            ScenarioTarget::Random { count } => {
                let mut candidates: Vec<usize> = network
                    .nodes
                    .iter()
                    .enumerate()
                    .filter(|(_, n)| n.state.mode != Mode::Isolated)
                    .map(|(idx, _)| idx)
                    .collect();

                candidates.shuffle(&mut rng());
                candidates.truncate(*count);
                candidates
            }

            ScenarioTarget::NeighborsOf(id) => {
                let Some(origin_idx) = network.nodes.iter().position(|n| n.id == *id) else {
                    return vec![];
                };
                let neighbor_ids: Vec<u32> = network
                    .links
                    .iter()
                    .filter(|l| l.active && l.from == origin_idx)
                    .map(|l| network.nodes[l.to].id)
                    .collect();

                neighbor_ids
                    .iter()
                    .filter_map(|nid| network.nodes.iter().position(|n| n.id == *nid))
                    .collect()
            }

            ScenarioTarget::All => (0..network.nodes.len()).collect(),
        }
    }
}


#[derive(Debug, Clone)]
pub enum ScenarioAction {
    InflateLoad { delta: i8 },
    InflateConnections { delta: i8 },
    InflateFailedAuth { delta: u8 },
    ForceMode { mode: Mode },
    AgeSync { seconds: u64 }, // Сдвигает last_sync_time в прошлое
    TagAiState { label: String }, // Подменяет current_ai_state строкой
    EmitLoadSignal { signal: SignalType },
    OverrideAI { enabled: bool }, // Включает/выключает подмену ИИ
}

impl ScenarioAction {
    fn apply_once(&self, node: &mut crate::node::Node) -> AppliedDelta {
        let state = &mut node.state;

        match self {
            ScenarioAction::InflateLoad { delta } => {
                let before = state.load;
                state.load = state.load.saturating_add_signed(*delta);
                AppliedDelta::Load(state.load as i16 - before as i16)
            }

            ScenarioAction::InflateConnections { delta } => {
                let before = state.active_connections;
                state.active_connections = state.active_connections.saturating_add_signed(*delta);
                AppliedDelta::Connections(state.active_connections as i32 - before as i32)
            }

            ScenarioAction::InflateFailedAuth { delta } => {
                let before = state.failed_auth_count;
                state.failed_auth_count = state.failed_auth_count.saturating_add(*delta);
                AppliedDelta::FailedAuth(state.failed_auth_count as i16 - before as i16)
            }

            ScenarioAction::ForceMode { mode } => {
                let before = state.mode;
                state.mode = *mode;
                AppliedDelta::Mode { before }
            }

            ScenarioAction::AgeSync { seconds } => {
                let before = state.last_sync_time;
                state.last_sync_time = state.last_sync_time.saturating_sub(*seconds);
                AppliedDelta::Sync { before }
            }

            ScenarioAction::TagAiState { label } => {
                let before = state.ai_state_reason.clone();
                state.ai_state_reason = label.clone();
                AppliedDelta::AiState { before }
            }

            ScenarioAction::EmitLoadSignal { signal } => {
                state.pending_load_signal = Some(signal.clone());
                AppliedDelta::NoOp
            }

            ScenarioAction::OverrideAI { enabled } => {
                let before = node.ai.is_overridden();
                node.ai.set_overridden(*enabled);
                AppliedDelta::AiOverride { before }
            }
        }
    }
}


#[derive(Debug, Clone)]
enum AppliedDelta {
    Load(i16),
    Connections(i32),
    FailedAuth(i16),
    Mode { before: Mode },
    Sync { before: u64 },
    AiState { before: String },
    AiOverride { before: bool },
    NoOp,
}

impl AppliedDelta {
    fn revert(self, network: &mut Network, node_idx: usize) {
        match self {
            AppliedDelta::Load(d) => {
                let state = &mut network.nodes[node_idx].state;
                state.load = (state.load as i16 - d).clamp(70, 120) as u8;
            }
            AppliedDelta::Connections(d) => {
                let state = &mut network.nodes[node_idx].state;
                state.active_connections = (state.active_connections as i32 - d).max(0) as u8;
            }
            AppliedDelta::FailedAuth(d) => {
                let state = &mut network.nodes[node_idx].state;
                state.failed_auth_count = (state.failed_auth_count as i16 - d).max(0) as u8;
            }
            AppliedDelta::Mode { before } => {
                network.nodes[node_idx].state.mode = before;
            }
            AppliedDelta::Sync { before } => {
                network.nodes[node_idx].state.last_sync_time = before;
            }
            AppliedDelta::AiState { before } => {
                network.nodes[node_idx].state.ai_state_reason = before;
            }
            AppliedDelta::AiOverride { before } => {
                network.nodes[node_idx].ai.set_overridden(before);
            }
            AppliedDelta::NoOp => {}
        }
    }
}

// Тип эффекта: мгновенный или растянутый
#[derive(Debug, Clone)]
pub enum EffectKind {
    Instant,
    Sustained {
        duration_ticks: u64,
        revert_on_expire: bool,
    },
}

// Сценарий — то, что выбирается снаружи (с веб-страницы)
#[derive(Debug, Clone)]
pub struct AttackScenario {
    pub name: String,
    pub target: ScenarioTarget,
    pub actions: Vec<ScenarioAction>,
    pub effect: EffectKind,
    pub cuts_links: bool,
}

impl AttackScenario {
    pub fn ddos(target: ScenarioTarget, duration_ticks: u64) -> Self {
        Self {
            name: "ddos".into(),
            target,
            actions: vec![
                ScenarioAction::InflateLoad { delta: 20 },
                ScenarioAction::InflateConnections { delta: 40 },
                ScenarioAction::TagAiState {
                    label: "high_load_anomalous_activity".into(),
                },
                // Делает атаку видимой соседям в тот же тик через broadcast-канал 
                ScenarioAction::EmitLoadSignal {
                    signal: SignalType::LoadReduced,
                },
            ],
            effect: EffectKind::Sustained {
                duration_ticks,
                revert_on_expire: true,
            },
            cuts_links: false,
        }
    }

    pub fn underscale(target: ScenarioTarget, duration_ticks: u64) -> Self {
        Self {
            name: "underscale".into(),
            target,
            actions: vec![
                ScenarioAction::InflateLoad { delta: -10 },
                ScenarioAction::InflateConnections { delta: -10 },
                ScenarioAction::TagAiState {
                    label: "load_below_normal".into(),
                },
                // Делает атаку видимой соседям в тот же тик через broadcast-канал 
                ScenarioAction::EmitLoadSignal {
                    signal: SignalType::LoadBoosted,
                },
            ],
            effect: EffectKind::Sustained {
                duration_ticks,
                revert_on_expire: true,
            },
            cuts_links: false,
        }
    }

    pub fn brute_force(target: ScenarioTarget, duration_ticks: u64) -> Self {
        Self {
            name: "brute_force".into(),
            target,
            actions: vec![
                ScenarioAction::InflateFailedAuth { delta: 5 },
                ScenarioAction::TagAiState {
                    label: "auth_bruteforce_detected".into(),
                },
            ],
            effect: EffectKind::Sustained {
                duration_ticks,
                revert_on_expire: true,
            },
            cuts_links: false,
        }
    }

    pub fn ai_crash(target: ScenarioTarget, duration_ticks: u64) -> Self {
        Self {
            name: "ai_crash".into(),
            target,
            actions: vec![
                ScenarioAction::ForceMode { mode: Mode::Degraded },
                ScenarioAction::OverrideAI { enabled: true },
                ScenarioAction::TagAiState {
                    label: "error".into(),
                },
            ],
            effect: EffectKind::Sustained {
                duration_ticks,
                revert_on_expire: true,
            },
            cuts_links: false,
        }
    }

    pub fn node_infection(target: ScenarioTarget, duration_ticks: u64) -> Self {
        Self {
            name: "node_infection".into(),
            target,
            actions: vec![
                ScenarioAction::InflateLoad { delta: 10 },
                ScenarioAction::InflateConnections { delta: 20 },
                ScenarioAction::AgeSync { seconds: 60 },
                ScenarioAction::TagAiState {
                    label: "malware_detected".into(),
                },
            ],
            effect: EffectKind::Sustained {
                duration_ticks,
                revert_on_expire: true,
            },
            cuts_links: false,
        }
    }

    pub fn network_partition(target: ScenarioTarget, duration_ticks: u64) -> Self {
        Self {
            name: "network_partition".into(),
            target,
            actions: vec![
                ScenarioAction::TagAiState {
                    label: "network_partitioned".into(), // не переиспользуем peer_consensus_isolation!
                },
            ],
            effect: EffectKind::Sustained { duration_ticks, revert_on_expire: true },
            cuts_links: true, // оставляем как сигнал ScenarioEngine::apply — но роль поменяется
        }
    }
}


pub struct ActiveEffect {
    pub scenario_name: String,
    pub target_node_indices: Vec<usize>,
    actions: Vec<ScenarioAction>,
    ticks_remaining: u64,
    revert_on_expire: bool,
    accumulated: HashMap<usize, Vec<AppliedDelta>>,
    partitioned_ids: Vec<u32>
}

// Движок применения — используется из Network
pub struct ScenarioEngine;

impl ScenarioEngine {
    pub fn apply(network: &mut Network, scenario: &AttackScenario) -> Option<ActiveEffect> {
        let indices = scenario.target.resolve(network);

        if indices.is_empty() {
            tracing::warn!(
                "Scenario '{}' resolved to zero targets — nothing applied",
                scenario.name
            );
            return None;
        }

        tracing::info!(
            "⚡ Applying scenario '{}' to node(s) {:?}",
            scenario.name,
            indices.iter().map(|&idx| network.nodes[idx].id).collect::<Vec<_>>()
        );

        let mut accumulated: HashMap<usize, Vec<AppliedDelta>> = HashMap::new();

        for &idx in &indices {
            let mut deltas = Vec::with_capacity(scenario.actions.len());
            for action in &scenario.actions {
                deltas.push(action.apply_once(&mut network.nodes[idx]));
            }
            accumulated.insert(idx, deltas);
        }

        let partitioned_ids: Vec<u32> = if scenario.cuts_links {
            let ids: Vec<u32> = indices.iter().map(|&idx| network.nodes[idx].id).collect();
            for &id in &ids {
                network.partitioned_nodes.insert(id);
            }
            ids
        } else {
            vec![]
        };

        match &scenario.effect {
            EffectKind::Instant => {
                None
            }

            EffectKind::Sustained { duration_ticks, revert_on_expire } => Some(ActiveEffect {
                scenario_name: scenario.name.clone(),
                target_node_indices: indices,
                actions: scenario.actions.clone(),
                ticks_remaining: duration_ticks.saturating_sub(1),
                revert_on_expire: *revert_on_expire,
                accumulated,
                partitioned_ids,
            }),
        }
    }

    pub fn advance_active_effects(network: &mut Network, mut effects: Vec<ActiveEffect>) -> Vec<ActiveEffect> {
        let mut still_active = Vec::with_capacity(effects.len());

        for mut effect in effects.drain(..) {
            if effect.ticks_remaining == 0 {
                if effect.revert_on_expire {
                    tracing::info!(
                        "⏹ Scenario '{}' expired — reverting {} target(s)",
                        effect.scenario_name,
                        effect.target_node_indices.len()
                    );
                    for (idx, deltas) in effect.accumulated.drain() {
                        if idx >= network.nodes.len() {
                            continue;
                        }

                        let node_id = network.nodes[idx].id;
                        let node_mode = network.nodes[idx].state.mode;
                        let mode_owned_by_system = matches!(node_mode, Mode::Isolated | Mode::Reconnecting)
                            && !effect.partitioned_ids.contains(&node_id);

                        for delta in deltas.into_iter().rev() {
                            if mode_owned_by_system && matches!(delta, AppliedDelta::Mode { .. } | AppliedDelta::AiOverride { .. }) {
                                continue;
                            }
                            delta.revert(network, idx);
                        }
                    }

                    // снимаем партицию отдельно от accumulated-механизма
                    for id in &effect.partitioned_ids {
                        network.partitioned_nodes.remove(id);
                    }
                } else {
                    tracing::info!("⏹ Scenario '{}' expired — effect left in place (no auto-revert)", effect.scenario_name);
                }
                continue;
            }

            for &idx in &effect.target_node_indices {
                if idx >= network.nodes.len() {
                    continue;
                }

                let node_mode = network.nodes[idx].state.mode;
                let escaped_scenario_control = matches!(node_mode, Mode::Isolated | Mode::Reconnecting)
                    && !effect.partitioned_ids.contains(&network.nodes[idx].id);

                if escaped_scenario_control {
                    tracing::info!(
                        "⏸ Scenario '{}' skipping re-apply on node {} — node left scenario control (now {:?})",
                        effect.scenario_name, network.nodes[idx].id, node_mode
                    );
                    continue;
                }

                let entry = effect.accumulated.entry(idx).or_default();
                for action in &effect.actions {
                    entry.push(action.apply_once(&mut network.nodes[idx]));
                }
            }

            effect.ticks_remaining -= 1;
            still_active.push(effect);
        }

        still_active
    }
}
