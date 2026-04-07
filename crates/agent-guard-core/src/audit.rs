use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::decision::{DecisionCode, GuardDecision};
use crate::types::Tool;

// ── AuditEvent ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub request_id: String,
    pub session_id: Option<String>,
    pub agent_id: Option<String>,
    pub actor: Option<String>,
    pub tool: String,
    pub payload_hash: Option<String>,
    pub decision: AuditDecision,
    pub code: Option<DecisionCode>,
    pub message: Option<String>,
    pub details: Option<serde_json::Value>,
    pub policy_version: String,
    pub matched_rule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    Allow,
    Deny,
    AskUser,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditRecord {
    ToolCall(AuditEvent),
    PolicyReload(ReloadEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReloadEvent {
    pub timestamp: DateTime<Utc>,
    pub status: ReloadStatus,
    pub old_version: String,
    pub new_version: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReloadStatus {
    Success,
    Failure,
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
        let record = AuditRecord::ToolCall(self.clone());
        serde_json::to_string(&record).unwrap_or_else(|e| {
            format!("{{\"error\":\"audit serialization failed: {e}\"}}")
        })
    }
}

impl ReloadEvent {
    pub fn success(old_version: String, new_version: String) -> Self {
        Self {
            timestamp: Utc::now(),
            status: ReloadStatus::Success,
            old_version,
            new_version: Some(new_version),
            error: None,
        }
    }

    pub fn failure(old_version: String, error: String) -> Self {
        Self {
            timestamp: Utc::now(),
            status: ReloadStatus::Failure,
            old_version,
            new_version: None,
            error: Some(error),
        }
    }

    pub fn to_jsonl(&self) -> String {
        let record = AuditRecord::PolicyReload(self.clone());
        serde_json::to_string(&record).unwrap_or_else(|e| {
            format!("{{\"error\":\"audit serialization failed: {e}\"}}")
        })
    }
}
