use std::path::PathBuf;

use pyo3::prelude::*;

use agent_guard_sdk::{Context, Guard, GuardDecision, Tool, TrustLevel};

use crate::error::GuardError;

// ── PyDecision ────────────────────────────────────────────────────────────────

/// Result of a `Guard.check()` call.
///
/// Attributes
/// ----------
/// outcome : str
///     One of ``"allow"``, ``"deny"``, or ``"ask_user"``.
/// message : str | None
///     Human-readable explanation for ``deny`` and ``ask_user`` outcomes.
/// code : str | None
///     Machine-readable decision code, e.g. ``"DENIED_BY_RULE"``.
/// matched_rule : str | None
///     Which policy rule triggered the decision, e.g. ``"tools.bash.deny[0]"``.
/// ask_prompt : str | None
///     The question to surface to the user; only present for ``"ask_user"``.
#[pyclass(module = "agent_guard")]
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

#[pyclass(module = "agent_guard")]
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
}

#[pymethods]
impl ExecuteResult {
    fn is_executed(&self) -> bool { self.status == "executed" }
    fn is_denied(&self) -> bool { self.status == "denied" }
    fn is_ask(&self) -> bool { self.status == "ask_required" }
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

/// Policy-enforcing guard for AI agent tool calls.
///
/// Construction
/// ------------
/// Use :meth:`from_yaml` or :meth:`from_yaml_file` — do not call ``__init__`` directly.
///
/// Example
/// -------
/// .. code-block:: python
///
///     import agent_guard
///     guard = agent_guard.Guard.from_yaml(\"version: 1\\ndefault_mode: workspace_write\\n\")
///     d = guard.check(\"bash\", \"ls -la\", trust_level=\"trusted\")
///     assert d.is_allow()
#[pyclass(name = "Guard", module = "agent_guard")]
pub struct PyGuard {
    inner: Guard,
}

#[pymethods]
impl PyGuard {
    /// Construct a Guard from a YAML string.
    ///
    /// Raises :exc:`GuardError` on parse or initialisation failure.
    #[staticmethod]
    fn from_yaml(yaml: &str) -> PyResult<Self> {
        let inner = Guard::from_yaml(yaml)
            .map_err(|e| GuardError::new_err(format!("{e}")))?;
        Ok(Self { inner })
    }

    /// Construct a Guard from a YAML file path.
    ///
    /// Raises :exc:`GuardError` on I/O, parse, or initialisation failure.
    #[staticmethod]
    fn from_yaml_file(path: &str) -> PyResult<Self> {
        let inner = Guard::from_yaml_file(path)
            .map_err(|e| GuardError::new_err(format!("{e}")))?;
        Ok(Self { inner })
    }

    /// Check whether a tool call is allowed by policy.
    ///
    /// Parameters
    /// ----------
    /// tool : str
    ///     Tool name: ``"bash"``, ``"read_file"``, ``"write_file"``,
    ///     ``"http_request"``, or a custom tool id.
    /// payload : str
    ///     Raw JSON string. For ``read_file``/``write_file`` use
    ///     ``{"path": "..."}``; for ``http_request`` use ``{"url": "..."}``.
    /// trust_level : str
    ///     One of ``"untrusted"`` (default), ``"trusted"``, or ``"admin"``.
    /// agent_id : str | None
    ///     Optional identifier for the agent making the call.
    /// session_id : str | None
    ///     Optional session identifier for audit correlation.
    /// actor : str | None
    ///     Optional human actor identifier.
    /// working_directory : str | None
    ///     Workspace root path. Used by the bash validator for
    ///     workspace-write boundary enforcement.
    ///
    /// Returns
    /// -------
    /// Decision
    ///     The enforcement decision.
    ///
    /// Raises
    /// ------
    /// GuardError
    ///     On invalid ``tool`` or ``trust_level`` values.
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

    /// Securely execute a tool command using the default sandbox for the current platform.
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

        let result = self.inner.execute_default(&input)
            .map_err(|e| GuardError::new_err(format!("Execution failed: {e}")))?;

        match result {
            agent_guard_sdk::ExecuteOutcome::Executed { output, policy_version } => {
                Ok(ExecuteResult {
                    status: "executed".to_string(),
                    output: Some(SandboxOutput {
                        stdout: output.stdout,
                        stderr: output.stderr,
                        exit_code: output.exit_code,
                    }),
                    decision: None,
                    policy_version,
                })
            }
            agent_guard_sdk::ExecuteOutcome::Denied { decision, policy_version } => {
                Ok(ExecuteResult {
                    status: "denied".to_string(),
                    output: None,
                    decision: Some(decision_from_rust(decision, policy_version.clone())),
                    policy_version,
                })
            }
            agent_guard_sdk::ExecuteOutcome::AskRequired { decision, policy_version } => {
                Ok(ExecuteResult {
                    status: "ask_required".to_string(),
                    output: None,
                    decision: Some(decision_from_rust(decision, policy_version.clone())),
                    policy_version,
                })
            }
        }
    }

    /// Atomically reload the policy from a YAML string.
    ///
    /// Raises :exc:`GuardError` on validation failure. The old policy
    /// remains active if the reload fails.
    fn reload_from_yaml(&self, yaml: &str) -> PyResult<()> {
        self.inner
            .reload_from_yaml(yaml)
            .map_err(|e| GuardError::new_err(format!("{e}")))
    }

    /// Return the SHA-256 version hash of the currently loaded policy.
    fn policy_version(&self) -> String {
        self.inner.policy_version()
    }

    /// Alias for policy_version(). [Deprecated: use policy_version instead]
    fn policy_hash(&self) -> String {
        self.inner.policy_version()
    }

    fn __repr__(&self) -> String {
        format!("Guard(policy_version={:?})", self.inner.policy_version())
    }
}
