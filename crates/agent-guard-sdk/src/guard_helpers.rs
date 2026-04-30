//! Small free helpers used internally by `Guard`.
//!
//! These are intentionally crate-private; callers should reach for the
//! `Guard` API rather than these primitives.

use agent_guard_core::{
    Context, DecisionCode, GuardDecision, GuardInput, PolicyMode, RuntimeDecision, Tool,
};
use agent_guard_validators::bash::PermissionMode;

use crate::executors::payload_declares_mutation_http;

pub(crate) fn runtime_decision_for_input(
    input: &GuardInput,
    decision: GuardDecision,
) -> RuntimeDecision {
    match decision {
        GuardDecision::Allow => {
            let guard_owns_execution = matches!(input.tool, Tool::Bash | Tool::WriteFile)
                || (matches!(input.tool, Tool::HttpRequest)
                    && payload_declares_mutation_http(&input.payload));

            if guard_owns_execution {
                RuntimeDecision::Execute
            } else {
                RuntimeDecision::Handoff
            }
        }
        GuardDecision::Deny { reason } => RuntimeDecision::Deny { reason },
        GuardDecision::AskUser { message, reason } => {
            RuntimeDecision::AskForApproval { message, reason }
        }
    }
}

pub(crate) fn anomaly_subject(context: &Context) -> String {
    context
        .actor
        .clone()
        .or_else(|| context.agent_id.clone())
        .or_else(|| context.session_id.clone())
        .unwrap_or_else(|| "unknown".to_string())
}

pub(crate) fn policy_mode_to_permission_mode(mode: &PolicyMode) -> PermissionMode {
    match mode {
        PolicyMode::ReadOnly => PermissionMode::ReadOnly,
        PolicyMode::WorkspaceWrite => PermissionMode::WorkspaceWrite,
        PolicyMode::FullAccess => PermissionMode::DangerFullAccess,
        PolicyMode::Blocked => PermissionMode::Blocked,
    }
}

pub(crate) fn classify_block_reason(reason: &str) -> DecisionCode {
    if reason.contains("read-only mode") {
        DecisionCode::WriteInReadOnlyMode
    } else if reason.contains("destructive") {
        DecisionCode::DestructiveCommand
    } else if reason.contains("outside the configured workspace")
        || reason.contains("escapes the configured workspace")
        || reason.contains("outside workspace")
    {
        DecisionCode::PathOutsideWorkspace
    } else {
        DecisionCode::DeniedByRule
    }
}

pub(crate) fn sha256_hash(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}
