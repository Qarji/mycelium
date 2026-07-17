use crate::ai_module::AIOutput;


#[derive(Debug, Clone)]
pub struct Proposal {
    pub action: ProposalAction,
    pub threat_score: f32,
    pub predicted_state: String,
    pub event_reason: String,
    pub confidence: f32,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ProposalAction {
    ReduceLoad,
    IncreaseLoad,
    EnterIsolation,
    ExitIsolation,
    EnterDegraded,
    ExitDegraded,
    BeginReconnect,
    ExitCalibration,
    DoNothing,
}


impl From<AIOutput> for Proposal {
    fn from(output: AIOutput) -> Self {

        let action = match output.recommended_action.as_str() {
            "reduce_load" => ProposalAction::ReduceLoad,
            "increase_load" => ProposalAction::IncreaseLoad,
            "enter_isolation" => ProposalAction::EnterIsolation,
            "enter_degraded" => ProposalAction::EnterDegraded,
            "exit_degraded" => ProposalAction::ExitDegraded,
            "begin_reconnect" => ProposalAction::BeginReconnect,
            "exit_isolation" => ProposalAction::ExitIsolation,
            _ => ProposalAction::DoNothing,
        };

        Proposal {
            action,
            threat_score: output.threat_score,
            predicted_state: output.predicted_state,
            event_reason: output.event_reason,
            confidence: output.confidence
        }
    }
}