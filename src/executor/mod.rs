use crate::node::{NodeState, Mode, SignalType};
use crate::proposal::{Proposal, ProposalAction};
use crate::config::Config;
pub struct Executor;

impl Executor {
    pub fn apply(&self, proposal: &Proposal, state: &mut NodeState, cfg: &Config, current_tick: u64) {
        match proposal.action {
            ProposalAction::ReduceLoad => self.apply_reduce_load(state, cfg, current_tick),
            ProposalAction::IncreaseLoad => self.apply_increase_load(state, cfg, current_tick),

            ProposalAction::EnterDegraded => {
                state.mode = Mode::Degraded;
                state.state_entered_tick = current_tick;
            }
            
            ProposalAction::ExitDegraded => {
                state.mode = Mode::Normal;
                state.state_entered_tick = current_tick;
            }

            ProposalAction::EnterIsolation => {
                state.mode = Mode::Isolated;
                state.load_hold_ticks_left = 0;
                state.state_entered_tick = current_tick;
                state.pending_load_signal = Some(SignalType::Isolation);
            }

            ProposalAction::ExitIsolation => {
                state.mode = Mode::Normal;
                state.state_entered_tick = current_tick;
            }

            ProposalAction::BeginReconnect => {
                state.mode = Mode::Reconnecting;
                state.state_entered_tick = current_tick;
            }

            ProposalAction::ExitCalibration => {
                state.mode = Mode::Normal;
                state.state_entered_tick = current_tick;
                state.load_hold_ticks_left = 0;
            }

            ProposalAction::DoNothing => {}  // без state_entered_tick, т.к. состояние не изменилось
        }
    }

    fn apply_reduce_load(&self, state: &mut NodeState, cfg: &Config, current_tick: u64) {
        let lc = &cfg.load_calibration;

        let current = state.load as f32;
        // Целевое значение на этом шаге
        let target = (current * (1.0 - lc.reduce_factor))
            .max(lc.reduce_floor as f32)
            .round() as u8;

        let old_load = state.load;
        state.load = target;
        state.mode = Mode::Throttled;
        state.state_entered_tick = current_tick;

        // Масштабируем active_connections пропорционально снижению
        let reduction_ratio = if old_load > 0 {
            target as f32 / old_load as f32
        } else {
            1.0
        };
        // Connections снижаются медленнее нагрузки (conn_scale_factor < 1)
        let conn_delta = 1.0 - (1.0 - reduction_ratio) * lc.conn_scale_factor;
        let new_conns = ((state.active_connections as f32) * conn_delta).round() as u8;
        let floor_conns = (cfg.node_defaults.active_connections as f32 * 0.2).ceil() as u8;
        state.active_connections = new_conns.max(floor_conns);

        state.load_hold_ticks_left = lc.hold_ticks;
        // Уведомим соседей: "мы сбросили нагрузку"
        state.pending_load_signal = Some(SignalType::LoadReduced);

        tracing::info!(
            "ReduceLoad: {} → {} (conns {} → {}, hold {} ticks)",
            old_load, state.load,
            new_conns, state.active_connections,
            lc.hold_ticks
        );
    }

    fn apply_increase_load(&self, state: &mut NodeState, cfg: &Config, current_tick: u64) {
        let lc = &cfg.load_calibration;

        let current = state.load as f32;
        let target = (current * (1.0 + lc.boost_factor))
            .min(lc.boost_ceiling as f32)
            .round() as u8;

        let old_load = state.load;
        state.load = target;
        state.mode = Mode::Boosted;
        state.state_entered_tick = current_tick;

        let boost_ratio = if old_load > 0 {
            target as f32 / old_load as f32
        } else {
            1.0
        };
        let conn_delta = 1.0 + (boost_ratio - 1.0) * lc.conn_scale_factor;
        let new_conns = ((state.active_connections as f32) * conn_delta).round() as u8;

        let ceiling_conns = cfg.node_defaults.active_connections * 2;
        state.active_connections = new_conns.min(ceiling_conns);

        state.load_hold_ticks_left = lc.hold_ticks;
        state.pending_load_signal = Some(SignalType::LoadBoosted);

        tracing::info!(
            "IncreaseLoad: {} → {} (conns {} → {}, hold {} ticks)",
            old_load, state.load,
            new_conns, state.active_connections,
            lc.hold_ticks
        );
    }
}