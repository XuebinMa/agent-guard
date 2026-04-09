use std::path::PathBuf;

use pyo3::prelude::*;

use agent_guard_sdk::{Context, Guard, GuardDecision, Tool, TrustLevel};

use crate::error::GuardError;

// ── PyDecision ────────────────────────────────────────────────────────────────

#[pyclass(module = "agent_guard", from_py_object)]
#[derive(Clone)]
pub struct SandboxOutput {
    #[pyo3(get)]
    pub stdout: String,
    #[pyo3(get)]
    pub stderr: String,
    #[pyo3(get)]
    pub exit_code: i32,
}

#[pyclass(module = "agent_guard", from_py_object)]
#[derive(Clone)]
pub struct Decision {
    #[pyo3(get)]
    pub outcome: String,
    #[pyo3(get)]
    pub message: Option<String>,
    #[pyo3(get)]
    pub code: Option<String>,
    #[pyo3(get)]
    pub matched_rule: Option<String>,
    #[pyo3(get)]
    pub ask_prompt: Option<String>,
    #[pyo3(get)]
    pub policy_version: String,
}

#[pyclass(module = "agent_guard", from_py_object)]
#[derive(Clone)]
pub struct ExecuteResult {
    #[pyo3(get)]
    pub status: String, // "executed", "denied", "ask_required"
    #[pyo3(get)]
    pub output: Option<SandboxOutput>,
    #[pyo3(get)]
    pub decision: Option<Decision>,
    #[pyo3(get)]
    pub policy_version: String,
    #[pyo3(get)]
    pub receipt: Option<String>, // JSON-encoded receipt
}

#[pymethods]
impl ExecuteResult {
    fn is_executed(&self) -> bool {
        self.status == "executed"
    }
    fn is_denied(&self) -> bool {
        self.status == "denied"
    }
    fn is_ask(&self) -> bool {
        self.status == "ask_required"
    }
}

pub fn decision_from_rust(d: GuardDecision, policy_version: String) -> Decision {
    match d {
        GuardDecision::Allow => Decision {
            outcome: "allow".to_string(),
            message: None,
            code: None,
            matched_rule: None,
            ask_prompt: None,
            policy_version,
        },
        GuardDecision::Deny { reason } => Decision {
            outcome: "deny".to_string(),
            message: Some(reason.message),
            code: Some(format!("{:?}", reason.code)),
            matched_rule: reason.matched_rule,
            ask_prompt: None,
            policy_version,
        },
        GuardDecision::AskUser { message, reason } => Decision {
            outcome: "ask_user".to_string(),
            message: Some(reason.message),
            code: Some(format!("{:?}", reason.code)),
            matched_rule: reason.matched_rule,
            ask_prompt: Some(message),
            policy_version,
        },
    }
}

// ── Tool parsing ──────────────────────────────────────────────────────────────

pub fn parse_tool(tool_str: &str) -> PyResult<Tool> {
    use agent_guard_sdk::CustomToolId;
    match tool_str {
        "bash" => Ok(Tool::Bash),
        "read_file" => Ok(Tool::ReadFile),
        "write_file" => Ok(Tool::WriteFile),
        "http_request" => Ok(Tool::HttpRequest),
        other => {
            let id = CustomToolId::new(other)
                .map_err(|e| GuardError::new_err(format!("invalid tool id {other:?}: {e}")))?;
            Ok(Tool::Custom(id))
        }
    }
}

// ── TrustLevel parsing ────────────────────────────────────────────────────────

pub fn parse_trust(trust_str: &str) -> PyResult<TrustLevel> {
    match trust_str {
        "untrusted" => Ok(TrustLevel::Untrusted),
        "trusted" => Ok(TrustLevel::Trusted),
        "admin" => Ok(TrustLevel::Admin),
        other => Err(GuardError::new_err(format!(
            "unknown trust_level {other:?}; expected \"untrusted\", \"trusted\", or \"admin\""
        ))),
    }
}

// ── PyGuard ───────────────────────────────────────────────────────────────────

#[pyclass(name = "Guard", module = "agent_guard")]
pub struct PyGuard {
    inner: Guard,
}

#[pymethods]
impl PyGuard {
    #[staticmethod]
    fn from_yaml(yaml: &str) -> PyResult<Self> {
        let inner = Guard::from_yaml(yaml).map_err(|e| GuardError::new_err(format!("{e}")))?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn from_yaml_file(path: &str) -> PyResult<Self> {
        let inner = Guard::from_yaml_file(path).map_err(|e| GuardError::new_err(format!("{e}")))?;
        Ok(Self { inner })
    }

    /// Set the Ed25519 signing key for provenance receipts.
    /// The key must be a 32-byte hex-encoded string.
    fn set_signing_key(&self, hex_key: &str) -> PyResult<()> {
        use ed25519_dalek::SigningKey;
        let bytes = hex::decode(hex_key)
            .map_err(|e| GuardError::new_err(format!("Invalid hex key: {e}")))?;
        let key_array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| GuardError::new_err("Key must be exactly 32 bytes (64 hex characters)"))?;
        let signing_key = SigningKey::from_bytes(&key_array);
        self.inner.with_signing_key(signing_key);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        tool,
        payload,
        *,
        trust_level = "untrusted",
        agent_id = None,
        session_id = None,
        actor = None,
        working_directory = None,
    ))]
    fn check(
        &self,
        tool: &str,
        payload: &str,
        trust_level: &str,
        agent_id: Option<String>,
        session_id: Option<String>,
        actor: Option<String>,
        working_directory: Option<String>,
    ) -> PyResult<Decision> {
        let tool = parse_tool(tool)?;
        let trust_level = parse_trust(trust_level)?;
        let ctx = Context {
            trust_level,
            agent_id,
            session_id,
            actor,
            working_directory: working_directory.map(PathBuf::from),
        };
        let decision = self.inner.check_tool(tool, payload, ctx);
        Ok(decision_from_rust(decision, self.inner.policy_version()))
    }

    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        tool,
        payload,
        *,
        trust_level = "untrusted",
        agent_id = None,
        session_id = None,
        actor = None,
        working_directory = None,
    ))]
    fn execute(
        &self,
        tool: &str,
        payload: &str,
        trust_level: &str,
        agent_id: Option<String>,
        session_id: Option<String>,
        actor: Option<String>,
        working_directory: Option<String>,
    ) -> PyResult<ExecuteResult> {
        let tool = parse_tool(tool)?;
        let trust_level = parse_trust(trust_level)?;
        let ctx = Context {
            trust_level,
            agent_id,
            session_id,
            actor,
            working_directory: working_directory.map(PathBuf::from),
        };
        let input = agent_guard_sdk::GuardInput {
            tool,
            payload: payload.to_string(),
            context: ctx,
        };

        let result = self
            .inner
            .execute_default(&input)
            .map_err(|e| GuardError::new_err(format!("Execution failed: {e}")))?;

        match result {
            agent_guard_sdk::ExecuteOutcome::Executed {
                output,
                policy_version,
                receipt,
            } => Ok(ExecuteResult {
                status: "executed".to_string(),
                output: Some(SandboxOutput {
                    stdout: output.stdout,
                    stderr: output.stderr,
                    exit_code: output.exit_code,
                }),
                decision: None,
                policy_version,
                receipt: receipt.map(|r| serde_json::to_string(&r).unwrap_or_default()),
            }),
            agent_guard_sdk::ExecuteOutcome::Denied {
                decision,
                policy_version,
            } => Ok(ExecuteResult {
                status: "denied".to_string(),
                output: None,
                decision: Some(decision_from_rust(decision, policy_version.clone())),
                policy_version,
                receipt: None,
            }),
            agent_guard_sdk::ExecuteOutcome::AskRequired {
                decision,
                policy_version,
            } => Ok(ExecuteResult {
                status: "ask_required".to_string(),
                output: None,
                decision: Some(decision_from_rust(decision, policy_version.clone())),
                policy_version,
                receipt: None,
            }),
        }
    }

    fn reload_from_yaml(&self, yaml: &str) -> PyResult<()> {
        self.inner
            .reload_from_yaml(yaml)
            .map_err(|e| GuardError::new_err(format!("{e}")))
    }

    fn policy_version(&self) -> String {
        self.inner.policy_version()
    }

    fn policy_hash(&self) -> String {
        self.inner.policy_hash()
    }

    fn __repr__(&self) -> String {
        format!("Guard(policy_version={:?})", self.inner.policy_version())
    }
}
