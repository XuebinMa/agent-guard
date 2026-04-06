use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::decision::{DecisionCode, GuardDecision};
use crate::types::Tool;

// ── AuditEvent ────────────────────────────────────────────────────────────────
//
// Fixed schema — field names and types are part of the public contract.
// Consumers (log aggregators, SIEM, UI) depend on this structure.
// Do NOT rename fields without a schema version bump.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub request_id: String,
    pub session_id: Option<String>,
    pub agent_id: Option<String>,
    pub actor: Option<String>,
    pub tool: String,
    /// SHA-256 hex digest of the raw payload string.
    /// None when audit.include_payload_hash = false.
    /// Raw payload is never logged.
    pub payload_hash: Option<String>,
    pub decision: AuditDecision,
    pub code: Option<DecisionCode>,
    pub message: Option<String>,
    pub details: Option<serde_json::Value>,
    /// The policy hash (instance version) used for this decision.
    pub policy_version: String,
    /// The policy rule path that triggered this decision, e.g. "tools.bash.deny[0]".
    /// None for Allow decisions (explainability not recorded at this stage).
    pub matched_rule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    Allow,
    Deny,
    AskUser,
}

impl AuditEvent {
    pub fn from_decision(
        request_id: String,
        tool: &Tool,
        payload: &str,
        decision: &GuardDecision,
        session_id: Option<String>,
        agent_id: Option<String>,
        actor: Option<String>,
        include_hash: bool,
        policy_version: String,
    ) -> Self {
        let payload_hash = if include_hash {
            let mut h = Sha256::new();
            h.update(payload.as_bytes());
            Some(hex::encode(h.finalize()))
        } else {
            None
        };

        let (audit_decision, code, message, details, matched_rule) = match decision {
            GuardDecision::Allow => (AuditDecision::Allow, None, None, None, None),
            GuardDecision::Deny { reason } => (
                AuditDecision::Deny,
                Some(reason.code.clone()),
                Some(reason.message.clone()),
                reason.details.clone(),
                reason.matched_rule.clone(),
            ),
            GuardDecision::AskUser { message, reason } => (
                AuditDecision::AskUser,
                Some(reason.code.clone()),
                Some(message.clone()),
                reason.details.clone(),
                reason.matched_rule.clone(),
            ),
        };

        Self {
            timestamp: Utc::now(),
            request_id,
            session_id,
            agent_id,
            actor,
            tool: tool.name(),
            payload_hash,
            decision: audit_decision,
            policy_version,
            code,
            message,
            details,
            matched_rule,
        }
    }

    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|e| {
            format!("{{\"error\":\"audit serialization failed: {e}\"}}")
        })
    }
}
