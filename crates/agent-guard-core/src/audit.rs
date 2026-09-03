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
    ExecutionStarted(ExecutionEvent),
    ExecutionFinished(ExecutionEvent),
    /// Outcome claimed by a host after execution left the Guard's boundary.
    /// Unlike `ExecutionFinished`, this is transcribed rather than witnessed.
    ExecutionReported(ExecutionEvent),
    SandboxFailure(SandboxFailureEvent),
    AnomalyTriggered(AnomalyEvent),
    AgentLocked(AnomalyEvent),
    ContentFinding(ContentFindingEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEvent {
    pub timestamp: DateTime<Utc>,
    pub request_id: String,
    pub agent_id: Option<String>,
    pub tool: String,
    pub sandbox_type: String,
    pub duration_ms: Option<u64>,
    pub exit_code: Option<i32>,
    /// A host's signature over the outcome it reported, when it supplied one.
    ///
    /// Only ever set on `ExecutionReported`, where the Guard did not witness
    /// the execution. `None` means the claim rests on nothing but the host
    /// having said it, and a reader must treat it that way rather than as an
    /// outcome that simply has not been checked yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_attestation: Option<crate::attestation::HostAttestation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxFailureEvent {
    pub timestamp: DateTime<Utc>,
    pub request_id: String,
    pub agent_id: Option<String>,
    pub tool: String,
    pub sandbox_type: String,
    pub error: String,
}

/// Audit record emitted when the content layer acts on an outbound payload
/// (S6-4c). Captures *what kind* of sensitive data was found and *how* it was
/// handled — never the raw matched content. Block-mode denials are recorded by
/// the normal `ToolCall` deny path, so this event covers `mask` and `warn`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentFindingEvent {
    pub timestamp: DateTime<Utc>,
    pub request_id: String,
    pub agent_id: Option<String>,
    pub tool: String,
    /// Content mode applied: `"mask"` or `"warn"`.
    pub mode: String,
    /// Finding-kind labels only (e.g. `"AWS Access Key"`, `"Email"`).
    pub labels: Vec<String>,
    /// Number of sensitive spans found.
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyEvent {
    pub timestamp: DateTime<Utc>,
    pub agent_id: Option<String>,
    pub actor: Option<String>,
    pub reason: String,
    /// What the verdict was derived from.
    ///
    /// `reason` is prose: it says a limit was exceeded, not which
    /// observations exceeded it. Without the evidence a reader can see that
    /// an actor was rate-limited or locked and cannot check whether the
    /// verdict follows. `None` marks a claim that carries no revalidation
    /// material — records written before this field, and any future emitter
    /// that does not supply one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<AnomalyEvidence>,
}

/// Which rule produced an anomaly verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyRule {
    /// Too many calls inside the window: fires when `observed > threshold`.
    RateLimit,
    /// Too many denials inside the window: fires when `observed >= threshold`.
    DenyFuse,
}

/// The observations a verdict was derived from, in a form another evaluator
/// can recompute it from.
///
/// The witnesses are wall-clock times so they mean something outside this
/// process. The decision itself is taken on a monotonic clock, which cannot
/// be moved by an NTP step or a hostile clock change; these two clocks are
/// deliberately different and are recorded together rather than one being
/// derived from the other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnomalyEvidence {
    pub rule: AnomalyRule,
    /// The width of the window the observations were counted in.
    pub window_seconds: u64,
    /// The configured limit the observations were compared against.
    pub threshold: usize,
    /// How many observations were counted. Equals `witnesses.len()` unless
    /// `truncated` is set.
    pub observed: usize,
    /// The in-window observations, oldest first.
    pub witnesses: Vec<DateTime<Utc>>,
    /// Set when the in-memory history hit its cap and older entries were
    /// dropped before this verdict. `observed` and `witnesses` then
    /// understate what happened, and a reader must treat the count as a
    /// lower bound rather than an exact reconstruction.
    pub truncated: bool,
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
    #[allow(clippy::too_many_arguments)]
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
                Some(reason.code),
                Some(reason.message.clone()),
                reason.details.clone(),
                reason.matched_rule.clone(),
            ),
            GuardDecision::AskUser { message, reason } => (
                AuditDecision::AskUser,
                Some(reason.code),
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
            tool: tool.name().to_string(),
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
        serde_json::to_string(&record)
            .unwrap_or_else(|e| format!("{{\"error\":\"audit serialization failed: {e}\"}}"))
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
        serde_json::to_string(&record)
            .unwrap_or_else(|e| format!("{{\"error\":\"audit serialization failed: {e}\"}}"))
    }
}
