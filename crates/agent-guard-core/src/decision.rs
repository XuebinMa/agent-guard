use serde::{Deserialize, Serialize};

// ── GuardDecision ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum GuardDecision {
    Allow,
    Deny { reason: DecisionReason },
    AskUser { message: String, reason: DecisionReason },
}

impl GuardDecision {
    pub fn deny(code: DecisionCode, message: impl Into<String>) -> Self {
        Self::Deny {
            reason: DecisionReason {
                code,
                message: message.into(),
                details: None,
                matched_rule: None,
            },
        }
    }

    pub fn deny_with_rule(
        code: DecisionCode,
        message: impl Into<String>,
        rule: impl Into<String>,
    ) -> Self {
        Self::Deny {
            reason: DecisionReason {
                code,
                message: message.into(),
                details: None,
                matched_rule: Some(rule.into()),
            },
        }
    }

    pub fn ask(
        message: impl Into<String>,
        code: DecisionCode,
        reason_msg: impl Into<String>,
    ) -> Self {
        Self::AskUser {
            message: message.into(),
            reason: DecisionReason {
                code,
                message: reason_msg.into(),
                details: None,
                matched_rule: None,
            },
        }
    }

    pub fn ask_with_rule(
        message: impl Into<String>,
        code: DecisionCode,
        reason_msg: impl Into<String>,
        rule: impl Into<String>,
    ) -> Self {
        Self::AskUser {
            message: message.into(),
            reason: DecisionReason {
                code,
                message: reason_msg.into(),
                details: None,
                matched_rule: Some(rule.into()),
            },
        }
    }

    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

// ── DecisionReason ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReason {
    pub code: DecisionCode,
    pub message: String,
    /// Structured extension fields for tooling, UI, and audit consumers.
    pub details: Option<serde_json::Value>,
    /// Which policy rule triggered this decision, e.g. "tools.bash.deny[0]".
    /// For Allow decisions, the matching allow rule is recorded in audit details instead.
    pub matched_rule: Option<String>,
}

// ── DecisionCode ──────────────────────────────────────────────────────────────
//
// Codes are part of the public contract — they appear in audit logs and
// bindings. Rename values only with a major version bump.

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(rename = "POLICY_LOAD_ERROR")]
    PolicyLoadError,
    #[serde(rename = "INTERNAL_ERROR")]
    InternalError,
}
