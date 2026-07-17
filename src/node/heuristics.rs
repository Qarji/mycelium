use super::{Node, Mode, NodeSignal, SignalType};
use crate::proposal::{Proposal, ProposalAction};
use std::collections::{HashSet,};

impl Node {
    pub fn process_load_advisories(&self, current_tick: u64) -> Option<Proposal> {
        let stale_ttl = self.config.security.stale_ttl;
        let neighbor_count = self.neighbor_ids.len();
        if neighbor_count == 0 {
            return None;
        }

        let reduce_votes = self.neighbor_signals.values().flatten()
            .filter(|s| {
                s.target_id.is_none()
                    && s.signal_type == SignalType::ReduceLoad
                    && current_tick.saturating_sub(s.timestamp) <= stale_ttl
            })
            .map(|s| s.source_id)
            .collect::<HashSet<_>>()
            .len();

        let boost_votes = self.neighbor_signals.values().flatten()
            .filter(|s| {
                s.target_id.is_none()
                    && s.signal_type == SignalType::BoostLoad
                    && current_tick.saturating_sub(s.timestamp) <= stale_ttl
            })
            .map(|s| s.source_id)
            .collect::<HashSet<_>>()
            .len();

        let majority = (neighbor_count / 2) + 1;

        // Позволяем Throttled-узлу дополнительно снижать нагрузку пошагово, если мы не на "дне"
        let can_reduce = matches!(self.state.mode, Mode::Normal | Mode::Throttled);
        if reduce_votes >= majority && can_reduce {
            if self.state.load > self.config.load_calibration.reduce_floor {
                tracing::info!(
                    "Node {} advisory reduce: {}/{} neighbors voted ReduceLoad (current mode: {:?})",
                    self.id, reduce_votes, neighbor_count, self.state.mode
                );
                return Some(Proposal {
                    action: ProposalAction::ReduceLoad,
                    threat_score: self.state.last_threat_score,
                    predicted_state: "high_load_network_overload".into(),
                    event_reason: format!(
                        "{}/{} neighbors signalled overload — reducing load further",
                        reduce_votes, neighbor_count
                    ),
                    confidence: reduce_votes as f32 / neighbor_count as f32,
                });
            }
        }

        // Позволяем Boosted-узлу дополнительно повышать нагрузку пошагово, если есть лимит
        let can_boost = matches!(self.state.mode, Mode::Normal | Mode::Boosted);
        if boost_votes >= majority && can_boost {
            if (self.state.load as f32) < self.config.load_calibration.boost_ceiling as f32 {
                tracing::info!(
                    "Node {} advisory boost: {}/{} neighbors voted BoostLoad (current mode: {:?})",
                    self.id, boost_votes, neighbor_count, self.state.mode
                );
                return Some(Proposal {
                    action: ProposalAction::IncreaseLoad,
                    threat_score: self.state.last_threat_score,
                    predicted_state: "load_on_network_has_increased".into(),
                    event_reason: format!(
                        "{}/{} neighbors signalled spare capacity — boosting load further",
                        boost_votes, neighbor_count
                    ),
                    confidence: boost_votes as f32 / neighbor_count as f32,
                });
            }
        }
        None
    }

    fn neighbors_norm_load(&self, current_tick: u64) -> f32 {
        let stale_ttl = self.config.security.stale_ttl;
        let fresh: Vec<_> = self.neighbor_signals.values().flatten()
            .filter(|s| current_tick.saturating_sub(s.timestamp) <= stale_ttl)
            .collect();
        if fresh.is_empty() {
            return self.config.node_defaults.load as f32;
        }
        fresh.iter().map(|s| s.load as f32).sum::<f32>() / fresh.len() as f32
    }

    pub fn process_overload_redistribution(&self, current_tick: u64) -> Option<Proposal> {
        if !matches!(self.state.mode, Mode::Normal | Mode::Throttled) {
            return None;
        }

        let stale_ttl = self.config.security.stale_ttl;
        let norm = self.neighbors_norm_load(current_tick);
        let boost_ceiling = self.config.load_calibration.boost_ceiling as f32;

        // Свободная ёмкость этого узла — сколько вообще можно взять
        let headroom = boost_ceiling - self.state.load as f32;
        if headroom <= 0.0 {
            return None;
        }

        // уникальные перегруженные соседи (Throttled + load выше нормы)
        let overloaded: Vec<&NodeSignal> = self.neighbor_signals.values().flatten()
            .filter(|s| {
                s.target_id.is_none()                                       // широковещательный
                    && s.signal_type == SignalType::LoadReduced
                    && s.mode == Mode::Throttled                             // уже среагировал сам
                    && s.load as f32 > norm                                  // всё равно перегружен
                    && current_tick.saturating_sub(s.timestamp) <= stale_ttl
            })
            // дедупликация по source_id — берём самый свежий сигнал от каждого
            .fold(std::collections::HashMap::<u32, &NodeSignal>::new(), |mut acc, s| {
                acc.entry(s.source_id)
                    .and_modify(|prev| { if s.timestamp > prev.timestamp { *prev = s; } })
                    .or_insert(s);
                acc
            })
            .into_values()
            .collect();

        if overloaded.is_empty() {
            return None;
        }

        let total_excess: f32 = overloaded.iter()
            .map(|s| (s.load as f32 - norm).max(0.0))
            .sum();

        let sources: Vec<u32> = {let mut ids: Vec<u32> = overloaded.iter().map(|s| s.source_id).collect(); ids.sort(); ids};

        tracing::info!(
            "Node {} overload-redistribution: {} overloaded neighbor(s) {:?}, \
             total_excess={:.1}, headroom={:.1}, norm={:.1}",
            self.id, overloaded.len(), sources, total_excess, headroom, norm
        );

        Some(Proposal {
            action: ProposalAction::IncreaseLoad,
            threat_score: self.state.last_threat_score,
            predicted_state: "high_load_neighbor_failure_relay".into(),
            event_reason: format!(
                "Neighbor(s) {:?} throttled but still overloaded (excess {:.0} above norm {:.0}) — absorbing share within headroom {:.0}",
                sources, total_excess, norm, headroom
            ),
            confidence: (total_excess / (total_excess + headroom)).min(1.0),
        })
    }

    pub fn process_underload_redistribution(&self, current_tick: u64) -> Option<Proposal> {
        if !matches!(self.state.mode, Mode::Normal | Mode::Boosted) {
            return None;
        }

        let stale_ttl = self.config.security.stale_ttl;
        let norm = self.neighbors_norm_load(current_tick);
        let reduce_floor = self.config.load_calibration.reduce_floor as f32;

        let reducible_load = self.state.load as f32 - reduce_floor;
        if reducible_load <= 0.0 {
            return None;
        }

        let underloaded: Vec<&NodeSignal> = self.neighbor_signals.values().flatten()
            .filter(|s| {
                s.target_id.is_none()
                    && s.mode == Mode::Boosted
                    && (s.load as f32) < norm 
                    && current_tick.saturating_sub(s.timestamp) <= stale_ttl
            })
            .fold(std::collections::HashMap::<u32, &NodeSignal>::new(), |mut acc, s| {
                acc.entry(s.source_id)
                    .and_modify(|prev| { if s.timestamp > prev.timestamp { *prev = s; } })
                    .or_insert(s);
                acc
            })
            .into_values()
            .collect();

        if underloaded.is_empty() {
            return None;
        }

        let total_deficit: f32 = underloaded.iter()
            .map(|s| (norm - s.load as f32).max(0.0))
            .sum();

        let sources: Vec<u32> = {
            let mut ids: Vec<u32> = underloaded.iter().map(|s| s.source_id).collect();
            ids.sort();
            ids
        };

        tracing::info!(
            "Node {} underload-redistribution: {} underloaded Boosted neighbor(s) {:?}, \
            total_deficit={:.1}, reducible={:.1}, norm={:.1}",
            self.id, underloaded.len(), sources, total_deficit, reducible_load, norm
        );

        Some(Proposal {
            action: ProposalAction::IncreaseLoad,
            threat_score: self.state.last_threat_score,
            predicted_state: "low_load_neighbor_failure_relay".into(),
            event_reason: format!(
                "Neighbor(s) {:?} Boosted but underloaded (deficit {:.0} below norm {:.0}) — shedding share to balance within floor",
                sources, total_deficit, norm
            ),
            confidence: (total_deficit / (total_deficit + reducible_load)).min(1.0),
        })
    }

    pub fn process_isolation_redistribution(&self, current_tick: u64) -> Option<Proposal> {
        if self.state.mode != Mode::Normal {
            return None;
        }

        let stale_ttl = self.config.security.stale_ttl;
        let boost_ceiling = self.config.load_calibration.boost_ceiling as f32;

        let headroom = boost_ceiling - self.state.load as f32;
        if headroom <= 0.0 {
            return None;
        }

        // Собираем уникальных соседей уходящих в изоляцию прямо сейчас
        let isolating: Vec<&NodeSignal> = self.neighbor_signals.values().flatten()
            .filter(|s| {
                s.target_id.is_none()
                    && s.signal_type == SignalType::Isolation
                    && current_tick.saturating_sub(s.timestamp) <= stale_ttl
            })
            .fold(std::collections::HashMap::<u32, &NodeSignal>::new(), |mut acc, s| {
                acc.entry(s.source_id)
                    .and_modify(|prev| { if s.timestamp > prev.timestamp { *prev = s; } })
                    .or_insert(s);
                acc
            })
            .into_values()
            .collect();

        if isolating.is_empty() {
            return None;
        }

        // Суммируем весь load пропавших узлов — это объём, который нужно покрыть
        let total_lost: f32 = isolating.iter().map(|s| s.load as f32).sum();

        let sources: Vec<u32> = {
            let mut ids: Vec<u32> = isolating.iter().map(|s| s.source_id).collect();
            ids.sort();
            ids
        };

        tracing::info!(
            "🔌 Node {} isolation-redistribution: {} node(s) {:?} entering isolation, total_lost={:.1}, headroom={:.1}",
            self.id, isolating.len(), sources, total_lost, headroom
        );

        Some(Proposal {
            action: ProposalAction::IncreaseLoad,
            threat_score: self.state.last_threat_score,
            predicted_state: "low_load_neighbor_failure_relay".into(),
            event_reason: format!(
                "Node(s) {:?} entering isolation (total load {:.0} dropped from network) — absorbing share within headroom {:.0}",
                sources, total_lost, headroom
            ),
            confidence: (total_lost / (total_lost + headroom)).min(1.0),
        })
    }

    pub fn load_pressure_still_active(&self, current_tick: u64) -> bool {
        let stale_ttl = self.config.security.stale_ttl;
        let neighbor_count = self.neighbor_ids.len();
        if neighbor_count == 0 {
            return false;
        }
        let majority = (neighbor_count / 2) + 1;

        match self.state.mode {
            Mode::Throttled => {
                let reduce_votes = self.neighbor_signals.values().flatten()
                    .filter(|s| s.target_id.is_none()
                        && s.signal_type == SignalType::ReduceLoad
                        && current_tick.saturating_sub(s.timestamp) <= stale_ttl)
                    .map(|s| s.source_id).collect::<HashSet<_>>().len();
                reduce_votes >= majority
            }
            Mode::Boosted => {
                let boost_votes = self.neighbor_signals.values().flatten()
                    .filter(|s| s.target_id.is_none()
                        && s.signal_type == SignalType::BoostLoad
                        && current_tick.saturating_sub(s.timestamp) <= stale_ttl)
                    .map(|s| s.source_id).collect::<HashSet<_>>().len();
                boost_votes >= majority
            }
            _ => false,
        }
    }
}