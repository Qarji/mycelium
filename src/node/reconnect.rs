use super::{Node, Mode, NodeSignal, SignalType};
use crate::proposal::{Proposal, ProposalAction};
use crate::persistence::{DecisionSource, StateChange,};
use std::collections::{HashSet,};

pub struct ReconnectState {
    pub started_at_tick: u64,
    pub confirmed_by: HashSet<u32>,
    pub attempts: u32,
}

impl Node {
    // Генерирует ReconnectRequest для каждого известного соседа из топологии
    pub fn generate_reconnect_requests(&self, tick: u64) -> Vec<NodeSignal> {
        if self.state.mode != Mode::Reconnecting {
            return vec![];
        }

        // Берём соседей из топологической карты — физические линки ещё деактивированы
        let known_neighbors: Vec<u32> = self.topology_map.snapshots
            .get(&self.id).map(|snap| snap.neighbors.iter().copied()
            .filter(|&id| id != self.id)
            .collect()).unwrap_or_default();

        known_neighbors.iter().map(|&target| NodeSignal {
            source_id: self.id,
            target_id: Some(target),
            mode: self.state.mode,
            load: self.state.load,
            active_connections: self.state.active_connections,
            failed_auth_count: self.state.failed_auth_count,
            threat_score: self.state.last_threat_score,
            ai_state_reason: self.state.ai_state_reason.clone(),
            signal_type: SignalType::ReconnectRequest,
            timestamp: tick,
        }).collect()
    }

    // Ack-сигнал в ответ на ReconnectRequest (подтверждение реконнекта)
    pub fn handle_reconnect_request(&self, request: &NodeSignal, tick: u64) -> Option<NodeSignal> {
        if matches!(self.state.mode, Mode::Isolated | Mode::Reconnecting | Mode::Degraded) {
            return None;
        }

        // Базовая проверка: узел заявляет о целостности и нет активных тревог
        let acceptable = request.ai_state_reason != "malware_detected"
            && request.failed_auth_count <= self.config.security.max_failed_auth
            && request.threat_score < self.config.security.threat_score_isolation;

        if !acceptable {
            tracing::info!("Node {} rejected reconnect from Node {} (auth={})", self.id, request.source_id, request.failed_auth_count);
            return None;
        }

        Some(NodeSignal {
            source_id: self.id,
            target_id: Some(request.source_id),
            mode: self.state.mode,
            load: self.state.load,
            active_connections: self.state.active_connections,
            failed_auth_count: self.state.failed_auth_count,
            ai_state_reason: self.state.ai_state_reason.clone(),
            threat_score: self.state.last_threat_score,
            signal_type: SignalType::ReconnectAck,
            timestamp: tick,
        })
    }

    // Узел получил Ack от соседа — возвращает true если набран кворум и можно переходить в Normal
    pub fn handle_reconnect_ack(&mut self, ack: &NodeSignal) -> bool {
        let reconnect: &mut ReconnectState = match &mut self.reconnect {
            Some(r) => r,
            None => return false,
        };

        reconnect.confirmed_by.insert(ack.source_id);

        // Кворум: те же ⅔, что и для изоляции
        let known_neighbor_count = self.topology_map.snapshots.get(&self.id)
            .map(|s| s.neighbors.len())
            .unwrap_or(self.neighbor_ids.len());
        let quorum = ((known_neighbor_count * 2 + 2) / 3).max(1);
        let confirmed = reconnect.confirmed_by.len();

        tracing::info!("Node {} reconnect acks: {}/{} (quorum {})",self.id, confirmed, known_neighbor_count, quorum);
        confirmed >= quorum
    }

    // Финальный переход: Reconnecting → Normal, сброс состояния реконнекта
    pub fn complete_reconnect(&mut self, tick: u64) {
        tracing::info!("✓ Node {} completed reconnect at tick {}, returning to Normal", self.id, tick);
        let before = self.snapshot_state();

        self.reconnect = None;
        self.state.active_connections = self.config.node_defaults.active_connections;
        self.state.last_sync_time = tick;
        let proposal = Proposal { 
            action: ProposalAction::ExitIsolation, 
            threat_score: self.state.last_threat_score, 
            predicted_state: "network_partition_healing".into(),
            event_reason: "Reconnect handshake completed — returning to normal operation".into(),
            confidence: 1.0          
        };

        let decision = self.supervisor.validate(&proposal, &self.state, &self.config, tick, &self.neighbor_signals);

        if decision.allowed {
            self.executor.apply(&proposal, &mut self.state, &self.config, tick);
            self.state.ai_state_reason = proposal.predicted_state.clone();
        }

        let after = self.snapshot_state();
        let change = StateChange::diff(&before, &after);
        self.pending_lifecycle.push(decision.into_lifecycle_entry(
            self.id, DecisionSource::DeterministicReconnectComplete, change,
        ));
    }

    pub fn tick_failed_reconnect(&mut self, current_tick: u64) {
        let Some(reconnect) = &mut self.reconnect else { return };

        reconnect.attempts += 1;
        reconnect.confirmed_by.clear();

        let limit = self.config.security.max_reconnect_attempts;
        tracing::info!(
            "Node {} reconnect failed tick {} — attempt {}/{}",
            self.id, current_tick, reconnect.attempts, limit
        );

        if reconnect.attempts < limit {
            return; // ещё есть попытки
        }

        // Лимит исчерпан — идёт через стандартный путь
        let proposal = Proposal {
            action: ProposalAction::EnterIsolation,
            threat_score: 1.0,
            predicted_state: "reconnect_timeout".into(),
            event_reason: "Integrity check failed — node state cannot be trusted".into(),
            confidence: 1.0
        };

        let before = self.snapshot_state();
        let decision = self.supervisor.validate(&proposal, &self.state, &self.config, current_tick, &self.neighbor_signals);

        if decision.allowed {
            self.executor.apply(&proposal, &mut self.state, &self.config, current_tick);
            self.state.ai_state_reason = proposal.predicted_state.clone();
            self.reconnect = None;
        }

        let after = self.snapshot_state();
        let change = StateChange::diff(&before, &after);
        self.pending_lifecycle.push(decision.into_lifecycle_entry(
            self.id, DecisionSource::DeterministicReconnectTimeout, change,
        ));
    }
}