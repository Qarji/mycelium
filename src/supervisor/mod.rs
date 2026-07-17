use crate::node::{NodeState, Mode, DecisionRecord, NodeSignal};
use crate::proposal::{Proposal, ProposalAction};
use crate::config::Config;
use std::collections::{HashMap, VecDeque};

pub struct Supervisor;

impl Supervisor {
    pub fn validate(&self, proposal: &Proposal, state: &NodeState, cfg: &Config, current_tick: u64, neighbor_signals: &HashMap<u32, VecDeque<NodeSignal>>) -> DecisionRecord {
        let nd = &cfg.node_defaults;
        let sec = &cfg.security;

        let mut latest_neighbor_states: HashMap<u32, &NodeSignal> = HashMap::new();
        for sig in neighbor_signals.values().flatten() {
            if current_tick.saturating_sub(sig.timestamp) <= sec.stale_ttl {
                let entry = latest_neighbor_states.entry(sig.source_id).or_insert(sig);
                if sig.timestamp > entry.timestamp {
                    *entry = sig; // самый свежий сигнал от каждого соседа
                }
            }
        }

        let active_neighbors = latest_neighbor_states.len();
        
        // Вычисление индексов сетевого давления
        let throttled_count = latest_neighbor_states.values().filter(|s| s.mode == Mode::Throttled || s.mode == Mode::Degraded).count();
        let boosted_count = latest_neighbor_states.values().filter(|s| s.mode == Mode::Boosted).count();

        // Флаги критических состояний сети (>50% узлов в экстремальных режимах)
        let network_starving = active_neighbors > 0 && boosted_count > active_neighbors / 2;

        let total_load: u32 = latest_neighbor_states.values().map(|s| s.load as u32).sum();
        let total_capacity: u32 = (active_neighbors as u32) * (cfg.load_calibration.boost_ceiling as u32);
        let network_utilization = if total_capacity > 0 { total_load as f32 / total_capacity as f32 } else { 0.0 };
        
        let is_security_threat = state.last_threat_score >= sec.threat_score_isolation || state.failed_auth_count > sec.max_failed_auth;
        let is_physically_unstable = state.temperature > nd.temperature  || state.load > nd.load;

        match proposal.action {
            ProposalAction::ReduceLoad => {
                let lc = &cfg.load_calibration;
                let mode_ok = matches!(state.mode, Mode::Normal | Mode::Boosted | Mode::Throttled);

                let has_room_to_reduce = state.load > lc.reduce_floor || state.temperature > nd.temperature;
                let load_or_temp_elevated = state.load > nd.load || state.temperature > nd.temperature;

                if network_starving && !load_or_temp_elevated {
                    return DecisionRecord {
                        tick: current_tick,
                        proposal: proposal.clone(),
                        allowed: false,
                        reason: format!("Network starving ({}/{} boosted) and node not overloaded — ReduceLoad blocked", boosted_count, active_neighbors),
                    };
                }

                if mode_ok && has_room_to_reduce && load_or_temp_elevated {
                    DecisionRecord {
                        tick: current_tick,
                        proposal: proposal.clone(),
                        allowed: true,
                        reason: "Load acceptable for reduction".into(),
                    }
                } else {
                    DecisionRecord {
                        tick: current_tick,
                        proposal: proposal.clone(),
                        allowed: false,
                        reason: if !mode_ok {
                            format!("Cannot reduce load from current mode ({:?})", state.mode)
                        } else if !has_room_to_reduce {
                            "Already at reduce floor — nothing left to cut".into()
                        } else {
                            "Load already within normal range".into()
                        },
                    }
                }
            }
            
            ProposalAction::IncreaseLoad => {
                let is_redistribution = matches!(proposal.predicted_state.as_str(), "low_load_neighbor_failure_relay" | "absorbing_neighbor_overload" | "absorbing_isolated_node_load" | "load_on_network_has_increased");

                if network_utilization > 0.85 && !is_redistribution {
                    return DecisionRecord {
                        tick: current_tick,
                        proposal: proposal.clone(),
                        allowed: false,
                        reason: format!("Network overloaded ({}/{} throttled) — IncreaseLoad blocked to prevent cascade", throttled_count, active_neighbors),
                    };
                }

                let lc = &cfg.load_calibration;
                let ok = matches!(state.mode, Mode::Normal | Mode::Throttled | Mode::Boosted) && (state.load as f32) < lc.boost_ceiling as f32 && !is_security_threat;

                DecisionRecord {
                    tick: current_tick,
                    proposal: proposal.clone(),
                    allowed: ok,
                    reason: if ok {
                        if is_redistribution {
                            "Redistribution approved: headroom available".into()
                        } else {
                            "Load increase approved: headroom available".into()
                        }
                    } else if is_security_threat {
                        format!("Cannot increase load: active security threat ({})", state.ai_state_reason)
                    } else if !matches!(state.mode, Mode::Normal | Mode::Throttled | Mode::Boosted) {
                        format!("Cannot increase load from current mode ({:?})", state.mode)
                    } else {
                        "Cannot increase load: already at boost ceiling".into()
                    },
                }
            }

            ProposalAction::EnterDegraded => {
                let allowed_mode = state.mode != Mode::Degraded && state.mode != Mode::Isolated;
                let valid_reason = proposal.predicted_state == "ai_module_offline";

                DecisionRecord {
                    tick: current_tick,
                    proposal: proposal.clone(),
                    allowed: allowed_mode && valid_reason,
                    reason: if !allowed_mode {
                        format!("Cannot enter Degraded from current mode ({:?})", state.mode)
                    } else if !valid_reason {
                        "EnterDegraded strictly requires 'ai_module_offline' state".into()
                    } else {
                        "AI failure confirmed, transitioning to Degraded mode".into()
                    },
                }
            }

            ProposalAction::ExitDegraded => {
                let in_degraded = state.mode == Mode::Degraded;
                let valid_reason = proposal.predicted_state == "ai_recovered";
                let safe_to_exit = !is_security_threat;

                DecisionRecord {
                    tick: current_tick,
                    proposal: proposal.clone(),
                    allowed: in_degraded && valid_reason && safe_to_exit,
                    reason: if !in_degraded {
                        format!("Cannot exit Degraded: node is in {:?} mode", state.mode)
                    } else if !valid_reason {
                        "ExitDegraded strictly requires 'ai_recovered' state".into()
                    } else if !safe_to_exit {
                        format!("Cannot exit Degraded: unresolved security threat ({})", state.ai_state_reason)
                    } else {
                        "AI module recovery confirmed, returning to Normal".into()
                    },
                }
            }

            ProposalAction::EnterIsolation => {
                let is_ai_isolation_reason = matches!(proposal.predicted_state.as_str(), "malware_detected" | "auth_bruteforce_detected"
                | "integrity_violation" | "peer_consensus_isolation" | "neighbor_cascade_failure" | "reconnect_timeout_failure");

                if  state.mode != Mode::Isolated && (is_ai_isolation_reason || state.failed_auth_count > sec.max_failed_auth || proposal.threat_score > sec.threat_score_isolation) {
                    DecisionRecord {
                        tick: current_tick,
                        proposal: proposal.clone(),
                        allowed: true,
                        reason: format!("Isolation approved: {}", proposal.predicted_state),
                    }
                } else {
                    DecisionRecord {
                        tick: current_tick,
                        proposal: proposal.clone(),
                        allowed: false,
                        reason: "Insufficient threat score and unrecognized AI reason for isolation".into(),
                    }
                }
            }

            ProposalAction::BeginReconnect => {
                let can_reconnect = state.mode == Mode::Isolated && !is_security_threat && !is_physically_unstable;

                DecisionRecord {
                    tick: current_tick,
                    proposal: proposal.clone(),
                    allowed: can_reconnect,
                    reason: if can_reconnect {
                        "Network conditions stable, reconnect approved".into()
                    } else {
                        if is_security_threat {
                            format!("Reconnect denied: unresolved security breach ({})", state.ai_state_reason)
                        } else {
                            "Reconnect denied: wrong mode or high auth failures".into()
                        }
                    },
                }
            }

            ProposalAction::ExitIsolation => {
                let in_reconnecting = state.mode == Mode::Reconnecting;
                let auth_ok = state.failed_auth_count <= sec.max_failed_auth;
                let no_new_threat = !is_security_threat;
                let can_exit = in_reconnecting && auth_ok && no_new_threat;

                DecisionRecord {
                    tick: current_tick,
                    proposal: proposal.clone(),
                    allowed: can_exit,
                    reason: if can_exit {
                        "Recovery process complete, returning to normal operations".into()
                    } else if !in_reconnecting {
                        format!("Cannot exit Isolation: node is in {:?} mode", state.mode)
                    } else if !no_new_threat {
                        format!("Exit denied: new security threat detected during reconnect ({})", state.ai_state_reason)
                    } else {
                        "Exit denied: auth failure count still above threshold".into()
                    },
                }
            }

            ProposalAction::ExitCalibration => {
                let in_calibration = matches!(state.mode, Mode::Boosted | Mode::Throttled);
                let hold_elapsed = state.load_hold_ticks_left == 0;

                let normalized_total_load: u32 = latest_neighbor_states.values().map(|s| {
                    if s.mode == Mode::Boosted {
                        (s.load as u32).min(nd.load as u32)
                    } else {
                        s.load as u32
                    }
                }).sum();

                let normal_capacity = (active_neighbors as u32) * (nd.load as u32);
                let relative_utilization = if normal_capacity > 0 {
                    normalized_total_load as f32 / normal_capacity as f32
                } else {
                    1.0
                };

                let overloaded_throttled_count = latest_neighbor_states.values()
                    .filter(|s| {
                        (s.mode == Mode::Throttled || s.mode == Mode::Degraded) 
                        && (s.load) > (cfg.load_calibration.boost_ceiling)
                    }).count();

                let network_congested = active_neighbors > 0 && (overloaded_throttled_count * 2 >= active_neighbors);
                let has_throttled_neighbors = throttled_count > 0;
                
                let self_overloaded = state.load > nd.load;

                let anomaly_persists = match state.mode {
                    Mode::Throttled => {
                        if self_overloaded {
                            true
                        } else {
                            relative_utilization > 1.15 || network_congested
                        }
                    }
                    Mode::Boosted => {
                        relative_utilization > 1.75 || has_throttled_neighbors
                    }
                    _ => false,
                };

                let allowed = in_calibration && hold_elapsed && !anomaly_persists;

                DecisionRecord {
                    tick: current_tick,
                    proposal: proposal.clone(),
                    allowed,
                    reason: if !in_calibration {
                        format!("Cannot exit calibration: node is in {:?} mode", state.mode)
                    } else if !hold_elapsed {
                        "Cannot exit calibration: hold period not yet elapsed".into()
                    } else if anomaly_persists {
                        format!(
                            "Cannot exit calibration: load anomaly persists (mode: {:?}, relative util: {:.2}, self overloaded: {})",
                            state.mode, relative_utilization, self_overloaded
                        )
                    } else {
                        "Calibration hold elapsed and metrics stabilized, returning to Normal".into()
                    },
                }
            }

            ProposalAction::DoNothing => DecisionRecord {
                tick: current_tick,
                proposal: proposal.clone(),
                allowed: true,
                reason: "No action required".into(),
            },
        }
    }
}