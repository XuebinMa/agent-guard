use std::path::PathBuf;

use pyo3::prelude::*;
use serde_json::Value;

use agent_guard_sdk::{
    Context, Guard, GuardDecision, HandoffResult as RustHandoffResult,
    PolicyVerification as RustPolicyVerification, RuntimeDecision as RustRuntimeDecision,
    RuntimeOutcome as RustRuntimeOutcome, Tool, TrustLevel,
};

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
    #[pyo3(get)]
    pub policy_verification_status: String,
    #[pyo3(get)]
    pub policy_verification_error: Option<String>,
}

#[pymethods]
impl Decision {
    fn is_allow(&self) -> bool {
        self.outcome == "allow"
    }

    fn is_deny(&self) -> bool {
        self.outcome == "deny"
    }

    fn is_ask(&self) -> bool {
        self.outcome == "ask_user"
    }

    fn __repr__(&self) -> String {
        format!("Decision(outcome={:?}, code={:?})", self.outcome, self.code)
    }
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
    #[pyo3(get)]
    pub sandbox_type: Option<String>,
    #[pyo3(get)]
    pub policy_verification_status: String,
    #[pyo3(get)]
    pub policy_verification_error: Option<String>,
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

#[pyclass(module = "agent_guard", from_py_object)]
#[derive(Clone)]
pub struct PolicyVerification {
    #[pyo3(get)]
    pub status: String,
    #[pyo3(get)]
    pub error: Option<String>,
}

pub fn policy_verification_from_rust(value: RustPolicyVerification) -> PolicyVerification {
    PolicyVerification {
        status: value.status_label().to_string(),
        error: value.error,
    }
}

// ── RuntimeDecision ───────────────────────────────────────────────────────────

#[pyclass(module = "agent_guard", from_py_object)]
#[derive(Clone)]
pub struct RuntimeDecision {
    /// One of "execute", "handoff", "deny", "ask_for_approval".
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
    #[pyo3(get)]
    pub policy_verification_status: String,
    #[pyo3(get)]
    pub policy_verification_error: Option<String>,
}

#[pymethods]
impl RuntimeDecision {
    fn is_execute(&self) -> bool {
        self.outcome == "execute"
    }

    fn is_handoff(&self) -> bool {
        self.outcome == "handoff"
    }

    fn is_deny(&self) -> bool {
        self.outcome == "deny"
    }

    fn is_ask_for_approval(&self) -> bool {
        self.outcome == "ask_for_approval"
    }

    fn __repr__(&self) -> String {
        format!(
            "RuntimeDecision(outcome={:?}, code={:?})",
            self.outcome, self.code
        )
    }
}

pub fn runtime_decision_from_rust(
    d: RustRuntimeDecision,
    policy_version: String,
    policy_verification: RustPolicyVerification,
) -> RuntimeDecision {
    let verification_status = policy_verification.status_label().to_string();
    let verification_error = policy_verification.error.clone();
    match d {
        RustRuntimeDecision::Execute => RuntimeDecision {
            outcome: "execute".to_string(),
            message: None,
            code: None,
            matched_rule: None,
            ask_prompt: None,
            policy_version,
            policy_verification_status: verification_status,
            policy_verification_error: verification_error,
        },
        RustRuntimeDecision::Handoff => RuntimeDecision {
            outcome: "handoff".to_string(),
            message: None,
            code: None,
            matched_rule: None,
            ask_prompt: None,
            policy_version,
            policy_verification_status: verification_status,
            policy_verification_error: verification_error,
        },
        RustRuntimeDecision::Deny { reason } => RuntimeDecision {
            outcome: "deny".to_string(),
            message: Some(reason.message),
            code: Some(format!("{:?}", reason.code)),
            matched_rule: reason.matched_rule,
            ask_prompt: None,
            policy_version,
            policy_verification_status: verification_status,
            policy_verification_error: verification_error,
        },
        RustRuntimeDecision::AskForApproval { message, reason } => RuntimeDecision {
            outcome: "ask_for_approval".to_string(),
            message: Some(reason.message),
            code: Some(format!("{:?}", reason.code)),
            matched_rule: reason.matched_rule,
            ask_prompt: Some(message),
            policy_version,
            policy_verification_status: verification_status,
            policy_verification_error: verification_error,
        },
    }
}

// ── RuntimeOutcome ────────────────────────────────────────────────────────────

#[pyclass(module = "agent_guard", from_py_object)]
#[derive(Clone)]
pub struct RuntimeOutcome {
    /// One of "executed", "handoff", "denied", "ask_for_approval".
    #[pyo3(get)]
    pub outcome: String,
    #[pyo3(get)]
    pub request_id: String,
    #[pyo3(get)]
    pub output: Option<SandboxOutput>,
    #[pyo3(get)]
    pub decision: Option<RuntimeDecision>,
    #[pyo3(get)]
    pub policy_version: String,
    #[pyo3(get)]
    pub sandbox_type: Option<String>,
    #[pyo3(get)]
    pub receipt: Option<String>,
    #[pyo3(get)]
    pub policy_verification_status: String,
    #[pyo3(get)]
    pub policy_verification_error: Option<String>,
}

#[pymethods]
impl RuntimeOutcome {
    fn is_executed(&self) -> bool {
        self.outcome == "executed"
    }

    fn is_handoff(&self) -> bool {
        self.outcome == "handoff"
    }

    fn is_denied(&self) -> bool {
        self.outcome == "denied"
    }

    fn is_ask_for_approval(&self) -> bool {
        self.outcome == "ask_for_approval"
    }

    fn __repr__(&self) -> String {
        format!(
            "RuntimeOutcome(outcome={:?}, request_id={:?})",
            self.outcome, self.request_id
        )
    }
}

pub fn runtime_outcome_from_rust(
    o: RustRuntimeOutcome,
    sandbox_type: Option<String>,
) -> RuntimeOutcome {
    match o {
        RustRuntimeOutcome::Executed {
            request_id,
            output,
            policy_version,
            receipt,
            policy_verification,
        } => {
            let verification_status = policy_verification.status_label().to_string();
            let verification_error = policy_verification.error.clone();
            RuntimeOutcome {
                outcome: "executed".to_string(),
                request_id,
                output: Some(SandboxOutput {
                    stdout: output.stdout,
                    stderr: output.stderr,
                    exit_code: output.exit_code,
                }),
                decision: None,
                policy_version,
                sandbox_type,
                receipt: receipt.map(|r| serde_json::to_string(&r).unwrap_or_default()),
                policy_verification_status: verification_status,
                policy_verification_error: verification_error,
            }
        }
        RustRuntimeOutcome::Handoff {
            request_id,
            policy_version,
            policy_verification,
        } => {
            // Mirror the Node binding: surface a `decision` field with the
            // "handoff" outcome so consumers that branch on `decision.outcome`
            // keep working even though the Rust Handoff variant carries no
            // reason/message of its own.
            let decision = runtime_decision_from_rust(
                RustRuntimeDecision::Handoff,
                policy_version.clone(),
                policy_verification.clone(),
            );
            RuntimeOutcome {
                outcome: "handoff".to_string(),
                request_id,
                output: None,
                decision: Some(decision),
                policy_version,
                sandbox_type: None,
                receipt: None,
                policy_verification_status: policy_verification.status_label().to_string(),
                policy_verification_error: policy_verification.error,
            }
        }
        RustRuntimeOutcome::Denied {
            request_id,
            reason,
            policy_version,
            policy_verification,
        } => {
            let decision = runtime_decision_from_rust(
                RustRuntimeDecision::Deny { reason },
                policy_version.clone(),
                policy_verification.clone(),
            );
            RuntimeOutcome {
                outcome: "denied".to_string(),
                request_id,
                output: None,
                decision: Some(decision),
                policy_version,
                sandbox_type,
                receipt: None,
                policy_verification_status: policy_verification.status_label().to_string(),
                policy_verification_error: policy_verification.error,
            }
        }
        RustRuntimeOutcome::AskForApproval {
            request_id,
            message,
            reason,
            policy_version,
            policy_verification,
        } => {
            let decision = runtime_decision_from_rust(
                RustRuntimeDecision::AskForApproval { message, reason },
                policy_version.clone(),
                policy_verification.clone(),
            );
            RuntimeOutcome {
                outcome: "ask_for_approval".to_string(),
                request_id,
                output: None,
                decision: Some(decision),
                policy_version,
                sandbox_type,
                receipt: None,
                policy_verification_status: policy_verification.status_label().to_string(),
                policy_verification_error: policy_verification.error,
            }
        }
    }
}

// ── HandoffResult ─────────────────────────────────────────────────────────────

/// Result reported by the host after executing a `RuntimeOutcome::Handoff`
/// action. Pass to `Guard.report_handoff_result(request_id, result)` to emit
/// a matching `ExecutionFinished` audit record and close the audit loop.
///
/// `stdout` is accepted for forward-compatibility but is currently not part
/// of the audit `ExecutionEvent` schema and is dropped after the call. This
/// keeps the Python surface symmetric with future SDK growth without locking
/// hosts into a Node-vs-Python diff today.
#[pyclass(module = "agent_guard")]
#[derive(Clone)]
pub struct HandoffResult {
    #[pyo3(get, set)]
    pub exit_code: i32,
    #[pyo3(get, set)]
    pub duration_ms: u64,
    #[pyo3(get, set)]
    pub stdout: Option<String>,
    #[pyo3(get, set)]
    pub stderr: Option<String>,
}

#[pymethods]
impl HandoffResult {
    #[new]
    #[pyo3(signature = (exit_code, duration_ms, stdout = None, stderr = None))]
    fn new(
        exit_code: i32,
        duration_ms: u64,
        stdout: Option<String>,
        stderr: Option<String>,
    ) -> Self {
        Self {
            exit_code,
            duration_ms,
            stdout,
            stderr,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "HandoffResult(exit_code={}, duration_ms={})",
            self.exit_code, self.duration_ms
        )
    }
}

pub fn handoff_result_to_rust(r: &HandoffResult) -> RustHandoffResult {
    RustHandoffResult {
        exit_code: r.exit_code,
        duration_ms: r.duration_ms,
        stderr: r.stderr.clone(),
    }
}

pub fn decision_from_rust(
    d: GuardDecision,
    policy_version: String,
    policy_verification: RustPolicyVerification,
) -> Decision {
    let verification_status = policy_verification.status_label().to_string();
    let verification_error = policy_verification.error.clone();
    match d {
        GuardDecision::Allow => Decision {
            outcome: "allow".to_string(),
            message: None,
            code: None,
            matched_rule: None,
            ask_prompt: None,
            policy_version,
            policy_verification_status: verification_status,
            policy_verification_error: verification_error,
        },
        GuardDecision::Deny { reason } => Decision {
            outcome: "deny".to_string(),
            message: Some(reason.message),
            code: Some(format!("{:?}", reason.code)),
            matched_rule: reason.matched_rule,
            ask_prompt: None,
            policy_version,
            policy_verification_status: verification_status,
            policy_verification_error: verification_error,
        },
        GuardDecision::AskUser { message, reason } => Decision {
            outcome: "ask_user".to_string(),
            message: Some(reason.message),
            code: Some(format!("{:?}", reason.code)),
            matched_rule: reason.matched_rule,
            ask_prompt: Some(message),
            policy_version,
            policy_verification_status: verification_status,
            policy_verification_error: verification_error,
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

fn normalize_payload(tool: &Tool, payload: &str) -> String {
    if matches!(tool, Tool::Bash) {
        if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(payload) {
            if map.get("command").is_some() {
                return payload.to_string();
            }
        }
        return serde_json::json!({ "command": payload }).to_string();
    }

    payload.to_string()
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

    #[staticmethod]
    fn from_signed_yaml(yaml: &str, public_key_hex: &str, signature_hex: &str) -> PyResult<Self> {
        let inner = Guard::from_signed_yaml(yaml, public_key_hex, signature_hex)
            .map_err(|e| GuardError::new_err(format!("{e}")))?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn from_signed_yaml_file(
        policy_path: &str,
        public_key_path: &str,
        signature_path: &str,
    ) -> PyResult<Self> {
        let inner = Guard::from_signed_yaml_file(policy_path, public_key_path, signature_path)
            .map_err(|e| GuardError::new_err(format!("{e}")))?;
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
        let payload = normalize_payload(&tool, payload);
        let trust_level = parse_trust(trust_level)?;
        let ctx = Context {
            trust_level,
            agent_id,
            session_id,
            actor,
            working_directory: working_directory.map(PathBuf::from),
        };
        let decision = self.inner.check_tool(tool, &payload, ctx);
        Ok(decision_from_rust(
            decision,
            self.inner.policy_version(),
            self.inner.policy_verification(),
        ))
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
        let payload = normalize_payload(&tool, payload);
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
            payload,
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
                policy_verification,
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
                sandbox_type: Some(Guard::default_sandbox().sandbox_type().to_string()),
                policy_verification_status: policy_verification.status_label().to_string(),
                policy_verification_error: policy_verification.error,
            }),
            agent_guard_sdk::ExecuteOutcome::Denied {
                decision,
                policy_version,
                policy_verification,
            } => Ok(ExecuteResult {
                status: "denied".to_string(),
                output: None,
                decision: Some(decision_from_rust(
                    decision,
                    policy_version.clone(),
                    policy_verification.clone(),
                )),
                policy_version,
                receipt: None,
                sandbox_type: None,
                policy_verification_status: policy_verification.status_label().to_string(),
                policy_verification_error: policy_verification.error,
            }),
            agent_guard_sdk::ExecuteOutcome::AskRequired {
                decision,
                policy_version,
                policy_verification,
            } => Ok(ExecuteResult {
                status: "ask_required".to_string(),
                output: None,
                decision: Some(decision_from_rust(
                    decision,
                    policy_version.clone(),
                    policy_verification.clone(),
                )),
                policy_version,
                receipt: None,
                sandbox_type: None,
                policy_verification_status: policy_verification.status_label().to_string(),
                policy_verification_error: policy_verification.error,
            }),
        }
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
    fn decide(
        &self,
        tool: &str,
        payload: &str,
        trust_level: &str,
        agent_id: Option<String>,
        session_id: Option<String>,
        actor: Option<String>,
        working_directory: Option<String>,
    ) -> PyResult<RuntimeDecision> {
        let tool = parse_tool(tool)?;
        let payload = normalize_payload(&tool, payload);
        let trust_level = parse_trust(trust_level)?;
        let ctx = Context {
            trust_level,
            agent_id,
            session_id,
            actor,
            working_directory: working_directory.map(PathBuf::from),
        };
        let decision = self.inner.decide_tool(tool, &payload, ctx);
        Ok(runtime_decision_from_rust(
            decision,
            self.inner.policy_version(),
            self.inner.policy_verification(),
        ))
    }

    /// High-level runtime entry point.
    ///
    /// Performs the full Check → Filter → Audit → Sandbox/Handoff pipeline
    /// and returns one of `RuntimeOutcome` variants:
    /// `executed`, `handoff`, `denied`, `ask_for_approval`.
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
    fn run(
        &self,
        tool: &str,
        payload: &str,
        trust_level: &str,
        agent_id: Option<String>,
        session_id: Option<String>,
        actor: Option<String>,
        working_directory: Option<String>,
    ) -> PyResult<RuntimeOutcome> {
        let tool = parse_tool(tool)?;
        let payload = normalize_payload(&tool, payload);
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
            payload,
            context: ctx,
        };

        let sandbox = Guard::default_sandbox();
        let sandbox_type = sandbox.sandbox_type().to_string();

        let outcome = self
            .inner
            .run(&input, sandbox.as_ref())
            .map_err(|e| GuardError::new_err(format!("runtime error: {e}")))?;

        Ok(runtime_outcome_from_rust(outcome, Some(sandbox_type)))
    }

    /// Report the outcome of a host-executed handoff back into the audit
    /// stream. Call this after the host runs an action returned by `run()`
    /// as `RuntimeOutcome::Handoff` so the audit log records a matching
    /// `ExecutionFinished` event with `tool == "handoff"`.
    fn report_handoff_result(&self, request_id: &str, result: &HandoffResult) {
        let rust_result = handoff_result_to_rust(result);
        self.inner.report_handoff_result(request_id, rust_result);
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

    fn policy_verification(&self) -> PolicyVerification {
        policy_verification_from_rust(self.inner.policy_verification())
    }

    fn __repr__(&self) -> String {
        "Guard(<policy loaded>)".to_string()
    }
}
