use super::{Node, Mode, NodeSignal, NeighborHistory, SignalType};
use crate::proposal::{Proposal, ProposalAction};
use crate::ai_module::{self, AIModel};
use crate::config::{Config};
use crate::persistence::{DecisionSource,};
use std::collections::{HashMap, VecDeque};


impl Node {
    pub fn self_check(&mut self, tick: u64) -> (Proposal, DecisionSource) {
        if let Some(mut proposal) = self.generate_ai_proposal(tick) {
            self.last_proposal = Some(proposal.clone());
            tracing::info!("Proposal generated: {:?}", proposal);

            let min_ticks = self.config.security.min_quarantine_ticks as usize;
            let is_secure = self.state.threat_score_history.len() >= min_ticks
                && self.state.threat_score_history.iter().rev().take(min_ticks).all(|&s| s < self.config.security.threat_score_normal)
                && self.state.failed_auth_count == 0;

            let is_physically_healthy = self.state.temperature <= self.config.node_defaults.temperature && self.state.load <= self.config.node_defaults.load;

            let ticks_in_isolation = tick.saturating_sub(self.state.state_entered_tick);
            let quarantine_passed = ticks_in_isolation >= self.config.security.min_quarantine_ticks;

            if self.state.mode == Mode::Isolated && proposal.action == ProposalAction::DoNothing {
                if is_secure && is_physically_healthy && quarantine_passed {
                    proposal.action = ProposalAction::BeginReconnect;
                    proposal.predicted_state = "recovery_conditions_met".into();
                    proposal.event_reason = "Threat score and physical metrics are stable. Quarantine period passed.".into();
                }
            }
            let source = DecisionSource::AiPredict {
                predicted_state: proposal.predicted_state.clone(),
                threat_score: proposal.threat_score,
                confidence: proposal.confidence,
            };

            (proposal, source)
        }
        else {
            let proposal = Proposal {
            action: ProposalAction::DoNothing, 
            threat_score: 1.0,
            predicted_state: "integrity_violation".into(), 
            event_reason: "Integrity check failed — node state cannot be trusted".into(), 
            confidence: 1.0 
            };
            let source = DecisionSource::AiPredict {
                predicted_state: proposal.predicted_state.clone(),
                threat_score: proposal.threat_score,
                confidence: proposal.confidence,
            };

            (proposal, source)
        }
    }

    // Оценить угрозу от конкретного соседа по его сигналу
    pub fn assess_neighbor_threat(ai: &mut AIModel, signal: &NodeSignal, cfg: &Config, current_tick: u64, history: &NeighborHistory, all_signals: &HashMap<u32, VecDeque<NodeSignal>>,) -> f32 {
        let input = ai_module::AIFeatureBuilder::build_neighbour_signs(signal, current_tick, history, all_signals, cfg.security.stale_ttl,);

        match ai.evaluate_neighbor(&input) {
            Ok(score) => score,
            Err(e) => {
                tracing::warn!("AI neighbor evaluation failed, falling back to heuristics: {}", e);
                let mut score = signal.threat_score;
                if matches!(signal.ai_state_reason.as_str(), "peer_consensus_isolation" | "neighbor_cascade_failure" | "reconnect_timeout_failure") { 
                    score += 0.4;
                }
                if matches!(signal.ai_state_reason.as_str(), "malware_detected" | "auth_bruteforce_detected" | "integrity_violation") { 
                    score += 0.7;
                }
                if signal.failed_auth_count > cfg.security.max_failed_auth {score += 0.2 * (signal.failed_auth_count as f32);}
                if matches!(signal.signal_type, SignalType::Alert | SignalType::Isolation) {score += 0.2;}
                score.min(1.0)
            }
        }
    }

    pub fn generate_ai_proposal(&mut self, tick: u64) -> Option<Proposal> {
        let ai_input = ai_module::AIFeatureBuilder::build(self, tick);
        
        let ai_output = match self.ai.predict(&ai_input) {
            Ok(v) => v,
            Err(e) => {
                tracing::info!("AI error: {}", e);
                return self.handle_ai_failure(tick);
            }
        };

        self.handle_ai_success(ai_output, tick)
    }

    // Обработка падения ИИ (возвращает Proposal на переход в Degraded спустя N тиков)
    fn handle_ai_failure(&mut self, tick: u64) -> Option<Proposal> {
        if self.state.ai_state_reason != "ai_module_offline" {
            self.state.ai_state_reason = "ai_module_offline".into();
            self.state.state_entered_tick = tick;
        }
        
        let ticks_to_degraded = self.config.ai.ticks_to_degraded; 
        if self.state.mode != Mode::Degraded && tick.saturating_sub(self.state.state_entered_tick) >= ticks_to_degraded {
            return Some(Proposal {
                action: ProposalAction::EnterDegraded,
                threat_score: self.state.last_threat_score,
                predicted_state: "ai_module_offline".into(),
                event_reason: format!("AI module failed for {} consecutive ticks", ticks_to_degraded),
                confidence: 1.0,
            });
        }
        
        None // ИИ упал, но время для паники еще не пришло
    }

    // Обработка успешного ответа ИИ (включая плавный выход из Degraded)
    fn handle_ai_success(&mut self, ai_output: impl Into<Proposal>, tick: u64) -> Option<Proposal> {
        let proposal: Proposal = ai_output.into();

        if self.state.mode == Mode::Degraded {
            if self.state.ai_state_reason == "ai_module_offline" {
                self.state.ai_state_reason = "ai_recovering".into();
                self.state.state_entered_tick = tick; 
            }

            let ticks_alive = tick.saturating_sub(self.state.state_entered_tick);
            let ticks_to_normal = self.config.ai.ticks_to_normal; 
            let is_active_proposal = matches!(
                proposal.action,
                ProposalAction::ReduceLoad | ProposalAction::IncreaseLoad | ProposalAction::EnterIsolation
            );

            if is_active_proposal {
                tracing::info!("AI proposes active action, exiting Degraded immediately");
                return Some(proposal);
            } 
            else if ticks_alive >= ticks_to_normal {
                return Some(Proposal {
                    action: ProposalAction::ExitDegraded,
                    threat_score: self.state.last_threat_score,
                    predicted_state: "ai_recovered".into(),
                    event_reason: format!("AI stable for {} ticks", ticks_to_normal),
                    confidence: 1.0,
                });
            } 
            else {
                return None; // ИИ восстанавливается, ждем
            }
        }

        Some(proposal)
    }
}