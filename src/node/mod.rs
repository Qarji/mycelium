#![allow(dead_code)]
use crate::supervisor::Supervisor;
use crate::executor::Executor;
use crate::proposal::{Proposal, ProposalAction};
use crate::network::{TopologyMap};
use crate::ai_module::{self, AIModel};
use crate::config::{Config};
use crate::persistence::{AiDecisionEntry, DecisionSource, LifecycleEntry, StateChange, StateSnapshot,};
use reconnect::{ReconnectState};
mod topology;
mod ai_processes;
mod reconnect;
mod heuristics;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;


#[derive(Debug, Clone)]
pub struct VirtualBridgeAttempt {
    pub bridge_to: u32,        // с кем пытаемся соединиться напрямую
    pub via_fallen_node: u32,  // кто был посредником и исчез из сети
    pub started_at_tick: u64,
    pub attempts: u32,
    pub initiated_by_us: bool,
}

#[derive(Debug)]
pub struct DecisionRecord {
    pub tick: u64,
    pub proposal: Proposal,
    pub allowed: bool,
    pub reason: String,
}

impl DecisionRecord {
    fn into_lifecycle_entry(self, node_id: u32, source: DecisionSource, change: StateChange) -> LifecycleEntry {
        LifecycleEntry::now(
            self.tick,
            node_id,
            source,
            format!("{:?}", self.proposal.action),
            self.proposal.predicted_state.clone(),
            self.proposal.event_reason.clone(),
            self.proposal.threat_score,
            self.proposal.confidence,
            self.allowed,
            self.reason,
            change,
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SignalType {
    Normal,
    Alert,
    Isolation,
    LoadReduced, // факт о
    ReduceLoad, // призыв к
    LoadBoosted, 
    BoostLoad,
    PeerSuspicion,
    ReconnectRequest,
    ReconnectAck, // установка реконнекта по запросу
    VirtualBridgeRequest,
    VirtualBridgeAck,
    VirtualBridgeReject,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NodeSignal {
    pub source_id: u32,    // id отправителя
    pub target_id: Option<u32>,  // id получателя

    pub mode: Mode,
    pub load: u8,
    pub active_connections: u8,
    pub failed_auth_count: u8,
    pub threat_score: f32, // оценка угрозы самим узлом
    pub ai_state_reason: String,
    pub signal_type: SignalType,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Default)]
pub struct NeighborHistory {
    pub last_signal: Option<NodeSignal>,
    pub mode_entered_tick: u64,
    pub recent_timestamps: VecDeque<u64>, // для расчёта частоты сигналов
    pub suspicion_votes_cast: u32,        // сколько раз МЫ подозревали этого соседа
    pub times_isolated: u32,              // сколько раз он реально уходил в Isolated
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Mode {
    Normal,
    Throttled, // вынужденное понижение пропускной способности
    Boosted, // вынужденное повышение п.с.
    Degraded,
    Isolated,
    Reconnecting,
}

#[derive(Debug)]
pub struct NodeState {
    pub load: u8,
    pub temperature: i8,

    pub active_connections: u8,
    pub failed_auth_count: u8,
    pub last_sync_time: u64,

    pub pending_load_signal: Option<SignalType>,
    pub load_hold_ticks_left: u64,

    pub ai_state_reason: String,
    pub state_entered_tick: u64,
    pub last_threat_score: f32,
    pub threat_score_history: VecDeque<f32>,

    pub mode: Mode,
}

pub struct Node {
    pub id: u32,
    pub state: NodeState,
    pub ai: AIModel,
    pub supervisor: Supervisor,
    pub executor: Executor,
    pub config: Arc<Config>,
    pub neighbor_signals: HashMap<u32, VecDeque<NodeSignal>>,
    pub last_proposal: Option<Proposal>,
    pub topology_map: TopologyMap,
    pub incoming_alerts: Vec<SignalType>,
    pub neighbor_ids: Vec<u32>,
    pub reconnect: Option<ReconnectState>,
    pub neighbor_history: HashMap<u32, NeighborHistory>,
    pub pending_lifecycle: Vec<LifecycleEntry>,
    pub pending_ai_decisions: Vec<AiDecisionEntry>,
    pub virtual_bridge_attempts: HashMap<u32, VirtualBridgeAttempt>,
    pub pending_virtual_bridge_signals: Vec<NodeSignal>,
}


impl Node {
    fn snapshot_state(&self) -> StateSnapshot {
        StateSnapshot {
            mode: format!("{:?}", self.state.mode),
            load: self.state.load,
            active_connections: self.state.active_connections,
            failed_auth_count: self.state.failed_auth_count,
        }
    }

    fn decide_and_apply(&mut self, proposal: Proposal, tick: u64, source: DecisionSource) -> bool {
        self.state.last_threat_score = proposal.threat_score;

        let before = self.snapshot_state();
        let decision = self.supervisor.validate(&proposal, &self.state, &self.config, tick, &self.neighbor_signals);
        let allowed = decision.allowed;

        if decision.allowed {
            self.executor.apply(&proposal, &mut self.state, &self.config, tick);
        }

        let after = self.snapshot_state();
        let change = StateChange::diff(&before, &after);

        let entry = decision.into_lifecycle_entry(self.id, source, change);
        self.pending_lifecycle.push(entry);

        allowed
    }

    fn update_threat_history(&mut self) {
        let max_history = (self.config.security.min_quarantine_ticks as usize) * 2; 

        self.state.threat_score_history.push_back(self.state.last_threat_score);

        while self.state.threat_score_history.len() > max_history {
            self.state.threat_score_history.pop_front();
        }
    }

    // ГЛАВНАЯ ФУНКЦИЯ
    pub fn tick(&mut self, tick: u64) {
        tracing::info!("=== NODE {} TICK ===", self.id);
        
        // Принудительные решения по сигналам соседей в обход ИИ
        if self.state.mode != Mode::Isolated && self.state.mode != Mode::Reconnecting {
            if let Some(forced_proposal) = self.process_incoming_signals(tick) {
                self.decide_and_apply(forced_proposal, tick, DecisionSource::ForcedByPeerConsensus);
                return;
            }
        }

        if self.state.mode == Mode::Isolated {
            let (proposal, source) = self.self_check(tick);

            self.state.last_threat_score = proposal.threat_score;
            tracing::info!("Node {} self-check → {:?}", self.id, proposal.action);
            self.update_threat_history();

            let before = self.snapshot_state();
            let decision = self.supervisor.validate(&proposal, &self.state, &self.config, tick, &self.neighbor_signals);
            tracing::info!("Supervisor on self-check: allowed={}, reason={}",decision.allowed, decision.reason);

            if decision.allowed {
                self.executor.apply(&proposal, &mut self.state, &self.config, tick);
                self.state.ai_state_reason = proposal.predicted_state.clone();
                self.reconnect = Some(ReconnectState {
                    started_at_tick: tick,
                    confirmed_by: HashSet::new(),
                    attempts: 0,
                });
                tracing::info!("Node {} → Reconnecting (reconnect state initialized)", self.id);
            }

            let after = self.snapshot_state();
            let change = StateChange::diff(&before, &after);
            self.pending_lifecycle.push(decision.into_lifecycle_entry(self.id, source, change));
            return;
        }

        if self.state.mode == Mode::Reconnecting {
            tracing::info!("Node {} waiting for reconnect acks...", self.id);
            let decision = DecisionRecord {
                tick,
                proposal: Proposal {
                    action: ProposalAction::DoNothing,
                    threat_score: self.state.last_threat_score,
                    predicted_state: "recovery_conditions_met".into(),
                    event_reason: "Waiting for reconnect quorum from neighbors".into(),
                    confidence: 1.0
                },
                allowed: true,
                reason: "Waiting for neighbor acks".into(),
            };

            self.pending_lifecycle.push(decision.into_lifecycle_entry(
                self.id, DecisionSource::WaitingForReconnectAcks, StateChange::default(),
            ));
            return;
        }

        if self.state.load_hold_ticks_left > 0 {
            self.state.load_hold_ticks_left -= 1;
            tracing::info!("Node {} holding {} ({} ticks left)", self.id, match self.state.mode { Mode::Throttled => "Throttled", _ => "Boosted" }, self.state.load_hold_ticks_left);
            self.update_threat_history();
            
            let decision = DecisionRecord {
                tick,
                proposal: Proposal {
                    action: ProposalAction::DoNothing,
                    threat_score: self.state.last_threat_score,
                    predicted_state: "calibration_hold".into(),
                    event_reason: format!(
                        "Holding calibration state for {} more tick(s)",
                        self.state.load_hold_ticks_left
                    ),
                    confidence: 1.0,
                },
                allowed: true,
                reason: "Load calibration hold period".into(),
            };
            self.state.last_threat_score = decision.proposal.threat_score;
            self.pending_lifecycle.push(decision.into_lifecycle_entry(
                self.id, DecisionSource::CalibrationHold, StateChange::default(),
            ));
            return;
        }

        let mut proposal_applied = false;

        if let Some(advisory_proposal) = self.process_load_advisories(tick) {
            let allowed = self.decide_and_apply(advisory_proposal, tick, DecisionSource::HeuristicLoadAdvisory);
            tracing::info!("Load advisory decision: allowed={}", allowed);
            if allowed {
                proposal_applied = true;
            }
        }

        if !proposal_applied {
            if let Some(isolation_proposal) = self.process_isolation_redistribution(tick) {
                let allowed = self.decide_and_apply(isolation_proposal, tick, DecisionSource::HeuristicIsolationRedistribution);
                tracing::info!("Isolation-redistribution decision: allowed={}", allowed);
                if allowed {
                    proposal_applied = true;
                }
            }
        }

        if !proposal_applied {
            if let Some(overload_proposal) = self.process_overload_redistribution(tick) {
                let allowed = self.decide_and_apply(overload_proposal, tick, DecisionSource::HeuristicOverloadRedistribution);
                tracing::info!("Overload-redistribution decision: allowed={}", allowed);
                if allowed {
                    proposal_applied = true;
                }
            }
        }

        if !proposal_applied {
            if let Some(underload_proposal) = self.process_underload_redistribution(tick) {
                let allowed = self.decide_and_apply(underload_proposal, tick, DecisionSource::HeuristicLoadAdvisory);
                if allowed { proposal_applied = true; }
            }
        }

        if !proposal_applied {
            if let Some(proposal) = self.generate_ai_proposal(tick) {
                self.last_proposal = Some(proposal.clone());
                self.state.last_threat_score = proposal.threat_score;
                tracing::info!("Proposal generated: {:?}", proposal);

                let decision = self.supervisor.validate(&proposal, &self.state, &self.config, tick, &self.neighbor_signals);
                tracing::info!(
                    "Supervisor decision: allowed={}, reason={}",
                    decision.allowed, decision.reason
                );
                
                let ai_input = ai_module::AIFeatureBuilder::build(self, tick);
                self.pending_ai_decisions.push(AiDecisionEntry::now(
                    tick,
                    self.id, 
                    ai_input.to_raw_metrics(),
                    proposal.predicted_state.clone(), 
                    proposal.event_reason.clone(),
                    proposal.threat_score, 
                    proposal.confidence,
                ));
                let ai_source = DecisionSource::AiPredict {
                    predicted_state: proposal.predicted_state.clone(),
                    threat_score: proposal.threat_score, 
                    confidence: proposal.confidence,
                };

                let before = self.snapshot_state();

                if decision.allowed {
                    self.executor.apply(&proposal, &mut self.state, &self.config, tick);
                    if proposal.action != ProposalAction::EnterDegraded && proposal.action != ProposalAction::ExitDegraded {
                        self.state.ai_state_reason = proposal.predicted_state;
                    }
                    if proposal.action != ProposalAction::DoNothing {
                        proposal_applied = true;
                    }
                }
                let after = self.snapshot_state();
                let change = StateChange::diff(&before, &after);
                self.pending_lifecycle.push(decision.into_lifecycle_entry(self.id, ai_source, change));
            }
        }

        if !proposal_applied && matches!(self.state.mode, Mode::Boosted | Mode::Throttled) {
            if self.load_pressure_still_active(tick) {
                self.state.load_hold_ticks_left = self.config.load_calibration.hold_ticks;
                let decision = DecisionRecord {
                    tick,
                    proposal: Proposal {
                        action: ProposalAction::DoNothing,
                        threat_score: self.state.last_threat_score,
                        predicted_state: "calibration_hold_extended".into(),
                        event_reason: format!("{:?} hold expired but direct pressure signals persist — extending hold", self.state.mode),
                        confidence: 1.0,
                    },
                    allowed: true,
                    reason: "Hysteresis: active broadcast signals".into(),
                };
                self.pending_lifecycle.push(decision.into_lifecycle_entry(
                    self.id, DecisionSource::CalibrationHold, StateChange::default(),
                ));
            } else {
                let proposal = Proposal {
                    action: ProposalAction::ExitCalibration,
                    threat_score: self.state.last_threat_score,
                    predicted_state: "normal_operation".into(),
                    event_reason: format!("{:?} hold period elapsed — requesting return to Normal", self.state.mode),
                    confidence: 1.0,
                };
                
                let allowed = self.decide_and_apply(proposal, tick, DecisionSource::CalibrationHold);
                
                if !allowed {
                    let adjust_proposal = match self.state.mode {
                        Mode::Throttled => Some(Proposal {
                            action: ProposalAction::ReduceLoad,
                            threat_score: self.state.last_threat_score,
                            predicted_state: "high_load_network_overload".into(),
                            event_reason: "Exit calibration rejected (anomaly persists) — reducing load further".into(),
                            confidence: 1.0,
                        }),
                        Mode::Boosted => Some(Proposal {
                            action: ProposalAction::IncreaseLoad,
                            threat_score: self.state.last_threat_score,
                            predicted_state: "load_on_network_has_increased".into(),
                            event_reason: "Exit calibration rejected (anomaly persists) — boosting load further".into(),
                            confidence: 1.0,
                        }),
                        _ => None,
                    };

                    let adjusted = if let Some(p) = adjust_proposal {
                        self.decide_and_apply(p, tick, DecisionSource::HeuristicLoadAdvisory)
                    } else {
                        false
                    };

                    self.state.load_hold_ticks_left = self.config.load_calibration.hold_ticks;
                    if adjusted {
                        tracing::info!("Node {} exit rejected — load adjusted step-wise further", self.id);
                    } else {
                        tracing::info!("Node {} exit rejected by Supervisor — calibration hold extended", self.id);
                    }
                }
            }
        }

        self.update_threat_history();
        tracing::info!("Current state: {:?}", self.state);
    }
}