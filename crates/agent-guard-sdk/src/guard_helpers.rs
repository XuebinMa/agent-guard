//! Small free helpers used internally by `Guard`.
//!
//! These are intentionally crate-private; callers should reach for the
//! `Guard` API rather than these primitives.

use agent_guard_core::{
    Context, DecisionCode, DecisionReason, GuardDecision, GuardInput, PolicyMode, RuntimeDecision,
    Tool,
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
        GuardDecision::AskUser {
            message, reason, ..
        } => RuntimeDecision::ask_for_approval_with_reason(message, reason),
        // Fail closed: an unrecognized decision kind maps to a deny, never Execute.
        _ => RuntimeDecision::Deny {
            reason: DecisionReason::new(
                DecisionCode::InternalError,
                "unrecognized guard decision; failing closed",
            ),
        },
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

/// The request payload restated once per canonical spelling of its URL, so
/// policy rules are also matched against what a client would connect to.
/// Everything but `url` is carried over, which keeps method-aware rules and
/// the read-only gate deciding on the same request.
pub(crate) fn canonical_http_payloads(payload: &str) -> Vec<CanonicalPayload> {
    use agent_guard_validators::http::{canonical_url_subjects, url_without_userinfo};

    let Ok(request) = serde_json::from_str::<serde_json::Value>(payload) else {
        return Vec::new();
    };
    let Some(url) = request.get("url").and_then(|url| url.as_str()) else {
        return Vec::new();
    };
    let restate = |subject: String| {
        let mut restated = request.clone();
        restated["url"] = serde_json::Value::String(subject);
        restated.to_string()
    };
    // Userinfo changes which host a textual prefix names, so that form is a
    // request to be decided in full. Every other spelling names the same
    // destination as the original: a rule that matches one of them applies,
    // but an allow rule written as `host:443/…` is not unmatched by `host/…`.
    let without_userinfo = url_without_userinfo(url).map(|subject| CanonicalPayload {
        payload: restate(subject),
        decided_in_full: true,
    });
    let spellings = canonical_url_subjects(url)
        .into_iter()
        .map(|subject| CanonicalPayload {
            payload: restate(subject),
            decided_in_full: false,
        });
    without_userinfo.into_iter().chain(spellings).collect()
}

/// One canonical restatement of a request, and how much of its decision is
/// taken over.
pub(crate) struct CanonicalPayload {
    pub(crate) payload: String,
    /// `true`: the whole decision applies, including a refusal for matching no
    /// allow rule. `false`: only a deny or ask rule that matched applies.
    pub(crate) decided_in_full: bool,
}

/// Whether a decision came from a rule that matched, as opposed to a mode or
/// an allow-list the payload matched nothing in.
pub(crate) fn decided_by_a_matching_rule(decision: &GuardDecision) -> bool {
    match decision {
        GuardDecision::Deny { reason } | GuardDecision::AskUser { reason, .. } => {
            reason.matched_rule().is_some()
        }
        _ => false,
    }
}
