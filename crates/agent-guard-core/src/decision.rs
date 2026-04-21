use serde::{Deserialize, Serialize};

// ── GuardDecision ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
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

// ── RuntimeDecision ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
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

impl DecisionReason {
    pub fn new(code: DecisionCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
            matched_rule: None,
        }
    }

    pub fn matched_rule(mut self, rule: impl Into<String>) -> Self {
        self.matched_rule = Some(rule.into());
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
}
