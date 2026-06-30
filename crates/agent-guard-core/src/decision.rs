use serde::{Deserialize, Serialize};

// ── GuardDecision ─────────────────────────────────────────────────────────────

// `GuardDecision` drives enforcement, so it is `Serialize`-only by design: it
// must never be reconstructed from external input. Deriving `Deserialize` would
// let untrusted JSON (`{"decision":"allow"}`) synthesize an `Allow` without
// passing through the policy engine. Audit/receipt consumers read the
// serialized form; they never deserialize it back to drive a decision.
// `#[non_exhaustive]`: pre-1.0 is the only window to reserve room for new
// decision kinds without a breaking change. Cross-crate `match` must carry a
// wildcard arm; constructing and destructuring the existing variants is
// unaffected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
#[non_exhaustive]
pub enum GuardDecision {
    Allow,
    Deny {
        reason: DecisionReason,
    },
    AskUser {
        message: String,
        reason: DecisionReason,
    },
}

impl std::fmt::Display for GuardDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny { reason } => write!(f, "deny ({:?}: {})", reason.code, reason.message),
            Self::AskUser { message, .. } => write!(f, "ask_user ({})", message),
        }
    }
}
impl GuardDecision {
    pub fn deny(code: DecisionCode, message: impl Into<String>) -> Self {
        Self::Deny {
            reason: DecisionReason::new(code, message),
        }
    }

    pub fn deny_with_rule(
        code: DecisionCode,
        message: impl Into<String>,
        rule: impl Into<String>,
    ) -> Self {
        Self::Deny {
            reason: DecisionReason::new(code, message).with_matched_rule(rule),
        }
    }

    pub fn ask(
        message: impl Into<String>,
        code: DecisionCode,
        reason_msg: impl Into<String>,
    ) -> Self {
        Self::ask_with_reason(message, DecisionReason::new(code, reason_msg))
    }

    pub fn ask_with_rule(
        message: impl Into<String>,
        code: DecisionCode,
        reason_msg: impl Into<String>,
        rule: impl Into<String>,
    ) -> Self {
        Self::ask_with_reason(
            message,
            DecisionReason::new(code, reason_msg).with_matched_rule(rule),
        )
    }

    /// Build an `AskUser` decision from a pre-assembled [`DecisionReason`],
    /// enforcing a non-empty user-facing prompt (a blank prompt would reach a
    /// human as an empty approval request). This is the single chokepoint for
    /// `AskUser` construction — callers must not build the variant via a struct
    /// literal, so the invariant cannot be bypassed in-crate.
    pub fn ask_with_reason(message: impl Into<String>, reason: DecisionReason) -> Self {
        let message = message.into();
        let message = if message.is_empty() {
            format!("Confirmation required ({:?})", reason.code())
        } else {
            message
        };
        Self::AskUser { message, reason }
    }

    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

// ── RuntimeDecision ──────────────────────────────────────────────────────────

// `#[non_exhaustive]`: reserve room for new runtime dispositions before 1.0.
// Cross-crate `match` must carry a wildcard arm.
//
// `Deserialize` is intentionally omitted (mirroring `GuardDecision`, see the
// module-level rationale): `RuntimeDecision` carries `Deny`/`AskForApproval`, so
// allowing untrusted JSON to synthesize one would let a caller forge a decision.
// It is produced in-process from a `GuardDecision`, never parsed from input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RuntimeDecision {
    Execute,
    Handoff,
    Deny {
        reason: DecisionReason,
    },
    AskForApproval {
        message: String,
        reason: DecisionReason,
    },
}

impl std::fmt::Display for RuntimeDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Execute => write!(f, "execute"),
            Self::Handoff => write!(f, "handoff"),
            Self::Deny { reason } => write!(f, "deny ({:?}: {})", reason.code, reason.message),
            Self::AskForApproval { message, .. } => write!(f, "ask_for_approval ({message})"),
        }
    }
}

impl RuntimeDecision {
    pub fn deny(code: DecisionCode, message: impl Into<String>) -> Self {
        Self::Deny {
            reason: DecisionReason::new(code, message),
        }
    }

    pub fn ask_for_approval(
        message: impl Into<String>,
        code: DecisionCode,
        reason_msg: impl Into<String>,
    ) -> Self {
        Self::AskForApproval {
            message: message.into(),
            reason: DecisionReason::new(code, reason_msg),
        }
    }
}

// ── DecisionReason ────────────────────────────────────────────────────────────

// Fields are `pub(crate)` so an emitted reason is immutable to external
// callers: once a `Deny`/`AskUser` is produced, downstream code can read its
// parts through the accessors below but cannot swap `code` or blank `message`
// to undermine the audit trail. Construction goes through `new` and the
// `with_*` builders (which always supply a non-empty `message`); `#[non_exhaustive]`
// additionally blocks cross-crate struct literals that could bypass them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DecisionReason {
    pub(crate) code: DecisionCode,
    pub(crate) message: String,
    /// Structured extension fields for tooling, UI, and audit consumers.
    pub(crate) details: Option<serde_json::Value>,
    /// Which policy rule triggered this decision, e.g. "tools.bash.deny[0]".
    /// For Allow decisions, the matching allow rule is recorded in audit details instead.
    pub(crate) matched_rule: Option<String>,
}

impl DecisionReason {
    pub fn new(code: DecisionCode, message: impl Into<String>) -> Self {
        // Enforce the always-non-empty invariant at the single construction
        // chokepoint rather than leaving it as a doc comment: an empty message
        // would surface as a blank deny reason or approval prompt and weaken the
        // audit trail. Substitute a code-derived placeholder instead of
        // panicking — constructors run on hot decision paths and must stay
        // panic-free.
        let message = message.into();
        let message = if message.is_empty() {
            format!("decision: {code:?}")
        } else {
            message
        };
        Self {
            code,
            message,
            details: None,
            matched_rule: None,
        }
    }

    /// The decision code. `DecisionCode` is `Copy`, so this returns by value.
    pub fn code(&self) -> DecisionCode {
        self.code
    }

    /// The human-readable reason message (always non-empty for emitted reasons).
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Structured extension details for tooling, UI, and audit consumers.
    pub fn details(&self) -> Option<&serde_json::Value> {
        self.details.as_ref()
    }

    /// The policy rule that triggered this decision, e.g. "tools.bash.deny[0]".
    pub fn matched_rule(&self) -> Option<&str> {
        self.matched_rule.as_deref()
    }

    pub fn with_matched_rule(mut self, rule: impl Into<String>) -> Self {
        self.matched_rule = Some(rule.into());
        self
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn with_condition(mut self, condition: impl Into<String>) -> Self {
        let mut obj = match self.details.take() {
            Some(serde_json::Value::Object(m)) => m,
            _ => serde_json::Map::new(),
        };
        obj.insert(
            "condition".to_string(),
            serde_json::Value::String(condition.into()),
        );
        obj.insert("condition_met".to_string(), serde_json::Value::Bool(true));
        self.details = Some(serde_json::Value::Object(obj));
        self
    }
}

// ── DecisionCode ──────────────────────────────────────────────────────────────
//
// Codes are part of the public contract — they appear in audit logs and
// bindings. Rename values only with a major version bump.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionCode {
    #[serde(rename = "INSUFFICIENT_PERMISSION_MODE")]
    InsufficientPermissionMode,
    #[serde(rename = "DENIED_BY_RULE")]
    DeniedByRule,
    #[serde(rename = "ASK_REQUIRED")]
    AskRequired,
    #[serde(rename = "DESTRUCTIVE_COMMAND")]
    DestructiveCommand,
    #[serde(rename = "WRITE_IN_READ_ONLY_MODE")]
    WriteInReadOnlyMode,
    #[serde(rename = "PATH_TRAVERSAL")]
    PathTraversal,
    #[serde(rename = "PATH_OUTSIDE_WORKSPACE")]
    PathOutsideWorkspace,
    #[serde(rename = "UNTRUSTED_PATH")]
    UntrustedPath,
    #[serde(rename = "INVALID_CUSTOM_TOOL_ID")]
    InvalidCustomToolId,
    #[serde(rename = "INVALID_PAYLOAD")]
    InvalidPayload,
    #[serde(rename = "MISSING_PAYLOAD_FIELD")]
    MissingPayloadField,
    #[serde(rename = "NOT_IN_ALLOW_LIST")]
    NotInAllowList,
    #[serde(rename = "POLICY_LOAD_ERROR")]
    PolicyLoadError,
    #[serde(rename = "POLICY_VERIFICATION_FAILED")]
    PolicyVerificationFailed,
    #[serde(rename = "INTERNAL_ERROR")]
    InternalError,
    #[serde(rename = "ANOMALY_DETECTED")]
    AnomalyDetected,
    #[serde(rename = "AGENT_LOCKED")]
    AgentLocked,
    #[serde(rename = "BLOCKED_BY_MODE")]
    BlockedByMode,
    #[serde(rename = "SENSITIVE_CONTENT_BLOCKED")]
    SensitiveContentBlocked,
    #[serde(rename = "APPROVAL_DENIED")]
    ApprovalDenied,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_accessors_expose_constructed_parts() {
        let reason = DecisionReason::new(DecisionCode::DeniedByRule, "blocked");

        assert_eq!(reason.code(), DecisionCode::DeniedByRule);
        assert_eq!(reason.message(), "blocked");
        assert_eq!(reason.details(), None);
        assert_eq!(reason.matched_rule(), None);
    }

    #[test]
    fn builders_attach_rule_and_details_without_mutating_message() {
        let details = serde_json::json!({ "k": "v" });
        let reason = DecisionReason::new(DecisionCode::PathOutsideWorkspace, "escape")
            .with_matched_rule("tools.bash.deny[0]")
            .with_details(details.clone());

        // Builders consume `self` by value and return a new reason; the
        // load-bearing `message` is never blanked along the way.
        assert_eq!(reason.message(), "escape");
        assert_eq!(reason.matched_rule(), Some("tools.bash.deny[0]"));
        assert_eq!(reason.details(), Some(&details));
    }

    #[test]
    fn decision_code_is_copy() {
        let code = DecisionCode::AgentLocked;
        let copied = code;
        // Both bindings remain usable: `DecisionCode` is `Copy`.
        assert_eq!(code, copied);
    }

    #[test]
    fn decision_reason_new_substitutes_empty_message() {
        // The always-non-empty invariant is enforced at construction, not just
        // documented.
        assert!(!DecisionReason::new(DecisionCode::DeniedByRule, "")
            .message()
            .is_empty());
    }

    #[test]
    fn deny_constructor_never_yields_empty_message() {
        let decision = GuardDecision::deny(DecisionCode::DeniedByRule, "");
        let message = match &decision {
            GuardDecision::Deny { reason } => reason.message(),
            _ => "",
        };
        assert!(!message.is_empty());
    }

    #[test]
    fn ask_with_reason_enforces_non_empty_prompt() {
        let reason = DecisionReason::new(DecisionCode::AskRequired, "needs review");
        let decision = GuardDecision::ask_with_reason("", reason);
        let prompt = match &decision {
            GuardDecision::AskUser { message, .. } => message.as_str(),
            _ => "",
        };
        assert!(!prompt.is_empty());
    }

    #[test]
    fn trust_level_orders_by_privilege() {
        use crate::types::TrustLevel;
        assert!(TrustLevel::Admin > TrustLevel::Trusted);
        assert!(TrustLevel::Trusted > TrustLevel::Untrusted);
    }

    #[test]
    fn policy_mode_orders_by_permissiveness() {
        use crate::policy::PolicyMode;
        assert!(PolicyMode::FullAccess > PolicyMode::WorkspaceWrite);
        assert!(PolicyMode::WorkspaceWrite > PolicyMode::ReadOnly);
        assert!(PolicyMode::ReadOnly > PolicyMode::Blocked);
    }
}
