use std::path::Path;
use std::sync::Arc;

use agent_guard_core::{
    AuditConfig, AuditEvent, Context, DecisionCode, GuardDecision, GuardInput, PolicyEngine,
    PolicyMode, ReloadEvent, Tool,
};
use agent_guard_sandbox::{Sandbox, SandboxContext, SandboxError, SandboxOutput};
use agent_guard_validators::bash::{validate_bash_command, PermissionMode, ValidationResult};
use arc_swap::ArcSwap;
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use crate::siem::SiemExporter;

// ── GuardInitError ────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum GuardInitError {
    #[error("policy error: {0}")]
    Policy(#[from] agent_guard_core::PolicyError),
    #[error("failed to open audit file '{path}': {source}")]
    AuditFileOpen {
        path: String,
        source: std::io::Error,
    },
    #[error("signing key load error: {0}")]
    SigningKeyLoad(String),
}

// ── Guard ─────────────────────────────────────────────────────────────────────

/// Main entry point for the agent-guard SDK.
/// Manages policy state with atomic reloading and snapshot isolation.
pub struct Guard {
    state: ArcSwap<GuardState>,
}

#[derive(Clone)]
struct GuardState {
    engine: Arc<PolicyEngine>,
    audit_cfg: AuditConfig,
    audit_file: Option<Arc<std::sync::Mutex<std::fs::File>>>,
    siem_exporter: Arc<SiemExporter>,
    signing_key: Option<ed25519_dalek::SigningKey>,
}

impl std::fmt::Debug for Guard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.load();
        f.debug_struct("Guard")
            .field("policy_version", &state.engine.version())
            .field("audit_enabled", &state.audit_cfg.enabled)
            .field("audit_output", &state.audit_cfg.output)
            .finish_non_exhaustive()
    }
}

impl Guard {
    /// Create a Guard from an already-parsed PolicyEngine.
    pub fn new(engine: PolicyEngine) -> Result<Self, GuardInitError> {
        let state = GuardState::new(Arc::new(engine))?;
        Ok(Self {
            state: ArcSwap::from_pointee(state),
        })
    }

    /// Construct a Guard from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, GuardInitError> {
        Self::new(PolicyEngine::from_yaml_str(yaml)?)
    }

    /// Construct a Guard from a YAML file.
    pub fn from_yaml_file(path: impl AsRef<std::path::Path>) -> Result<Self, GuardInitError> {
        Self::new(PolicyEngine::from_yaml_file(path)?)
    }

    /// Set the Ed25519 signing key for provenance receipts.
    pub fn with_signing_key(&self, key: ed25519_dalek::SigningKey) {
        let old_state = self.state.load();
        let mut new_state = (**old_state).clone();
        new_state.signing_key = Some(key);
        self.state.store(Arc::new(new_state));
    }

    /// Construct a Guard from a YAML string with an Ed25519 signing key for provenance.
    pub fn from_yaml_with_key(
        yaml: &str,
        key: ed25519_dalek::SigningKey,
    ) -> Result<Self, GuardInitError> {
        let guard = Self::from_yaml(yaml)?;
        guard.with_signing_key(key);
        Ok(guard)
    }

    /// Load a hex-encoded Ed25519 private key from a file and set it on this Guard.
    pub fn load_signing_key(&self, path: impl AsRef<Path>) -> Result<(), GuardInitError> {
        let hex_str = std::fs::read_to_string(path)
            .map_err(|e| GuardInitError::SigningKeyLoad(e.to_string()))?;
        let key = parse_hex_signing_key(hex_str.trim())?;
        self.with_signing_key(key);
        Ok(())
    }

    /// Atomically reload the policy engine from a new instance.
    pub fn reload_engine(&self, engine: PolicyEngine) -> Result<(), GuardInitError> {
        let old_state = self.state.load();
        let old_version = old_state.engine.version().to_string();
        let new_version = engine.version().to_string();

        let mut new_state = GuardState::new(Arc::new(engine))?;
        new_state.signing_key = old_state.signing_key.clone();
        self.state.store(Arc::new(new_state));

        let event = ReloadEvent::success(old_version, new_version);
        self.write_reload_audit(&event, &old_state);

        Ok(())
    }

    /// Atomically reload the policy from a YAML string.
    pub fn reload_from_yaml(&self, yaml: &str) -> Result<(), GuardInitError> {
        match PolicyEngine::from_yaml_str(yaml) {
            Ok(engine) => self.reload_engine(engine),
            Err(e) => {
                let old_state = self.state.load();
                let old_version = old_state.engine.version().to_string();
                let err = GuardInitError::Policy(e);
                let event = ReloadEvent::failure(old_version, err.to_string());
                self.write_reload_audit(&event, &old_state);
                Err(err)
            }
        }
    }

    /// Return the current policy version (alias for version)
    pub fn policy_version(&self) -> String {
        self.state.load().engine.version().to_string()
    }

    /// Return the SHA-256 hash of the currently loaded policy.
    pub fn policy_hash(&self) -> String {
        self.state.load().engine.hash().to_string()
    }

    pub fn check(&self, input: &GuardInput) -> GuardDecision {
        let state = self.state.load();
        let request_id = Uuid::new_v4().to_string();
        self.check_internal(input, &state, &request_id)
    }

    pub fn check_tool(
        &self,
        tool: Tool,
        payload: impl Into<String>,
        context: Context,
    ) -> GuardDecision {
        let state = self.state.load();
        let request_id = Uuid::new_v4().to_string();
        let input = GuardInput {
            tool,
            payload: payload.into(),
            context,
        };
        self.check_internal(&input, &state, &request_id)
    }

    fn check_internal(
        &self,
        input: &GuardInput,
        state: &GuardState,
        request_id: &str,
    ) -> GuardDecision {
        let metrics = crate::metrics::get_metrics();
        let agent_id = input
            .context
            .agent_id
            .clone()
            .unwrap_or_else(|| "default".to_string());

        metrics
            .policy_checks_total
            .get_or_create(&crate::metrics::ToolLabels {
                agent_id: agent_id.clone(),
                tool: input.tool.name().to_string(),
            })
            .inc();

        let anomaly_subject = anomaly_subject(&input.context);
        let anomaly_cfg = state.engine.anomaly_config();

        match crate::anomaly::get_detector().check(&anomaly_subject, anomaly_cfg) {
            crate::anomaly::AnomalyStatus::Normal => {}
            crate::anomaly::AnomalyStatus::RateLimited => {
                let decision = GuardDecision::deny(
                    DecisionCode::AnomalyDetected,
                    format!(
                        "anomaly detected: tool call frequency exceeded limit ({} calls / {}s)",
                        anomaly_cfg.rate_limit.max_calls, anomaly_cfg.rate_limit.window_seconds
                    ),
                );
                return self.finalize_check(input, &decision, state, &agent_id, "deny", request_id);
            }
            crate::anomaly::AnomalyStatus::Locked => {
                let decision = GuardDecision::deny(
                    DecisionCode::AgentLocked,
                    "anomaly detected: agent locked due to too many security denials (Deny Fuse)",
                );
                return self.finalize_check(input, &decision, state, &agent_id, "deny", request_id);
            }
        }

        let decision = self.evaluate(input, state);

        let outcome = match &decision {
            GuardDecision::Allow => "allow",
            GuardDecision::Deny { .. } => {
                crate::anomaly::get_detector().report_denial(&anomaly_subject, anomaly_cfg);
                "deny"
            }
            GuardDecision::AskUser { .. } => "ask",
        };
        self.finalize_check(input, &decision, state, &agent_id, outcome, request_id)
    }

    fn finalize_check(
        &self,
        input: &GuardInput,
        decision: &GuardDecision,
        state: &GuardState,
        agent_id: &str,
        outcome: &str,
        request_id: &str,
    ) -> GuardDecision {
        let metrics = crate::metrics::get_metrics();

        metrics
            .decision_total
            .get_or_create(&crate::metrics::DecisionLabels {
                agent_id: agent_id.to_string(),
                tool: input.tool.name().to_string(),
                outcome: outcome.to_string(),
            })
            .inc();

        if outcome == "deny"
            && matches!(decision, GuardDecision::Deny { reason } if reason.code == DecisionCode::AnomalyDetected || reason.code == DecisionCode::AgentLocked)
        {
            metrics
                .anomaly_triggered_total
                .get_or_create(&crate::metrics::ToolLabels {
                    agent_id: agent_id.to_string(),
                    tool: input.tool.name().to_string(),
                })
                .inc();

            let event = agent_guard_core::AnomalyEvent {
                timestamp: chrono::Utc::now(),
                agent_id: Some(agent_id.to_string()),
                actor: input.context.actor.clone(),
                reason: match decision {
                    GuardDecision::Deny { reason } => reason.message.clone(),
                    _ => "anomaly".to_string(),
                },
            };
            let record = if matches!(decision, GuardDecision::Deny { reason } if reason.code == DecisionCode::AgentLocked)
            {
                agent_guard_core::AuditRecord::AgentLocked(event)
            } else {
                agent_guard_core::AuditRecord::AnomalyTriggered(event)
            };
            state.siem_exporter.export(record);
        }

        if state.audit_cfg.enabled {
            self.write_audit(input, decision, state, request_id);
        }
        decision.clone()
    }

    pub fn execute(&self, input: &GuardInput, sandbox: &dyn Sandbox) -> ExecuteResult {
        // Industrial Standard: Single-snapshot isolation.
        let state = self.state.load();
        let request_id = Uuid::new_v4().to_string();
        let policy_version = state.engine.version().to_string();

        let decision = self.check_internal(input, &state, &request_id);
        match &decision {
            GuardDecision::Allow => {}
            GuardDecision::Deny { .. } => {
                return Ok(ExecuteOutcome::Denied {
                    decision,
                    policy_version,
                });
            }
            GuardDecision::AskUser { .. } => {
                return Ok(ExecuteOutcome::AskRequired {
                    decision,
                    policy_version,
                });
            }
        }

        // Enforcement mode (sandbox execution) is currently optimized for shell tools.
        let command = if let Tool::Bash = input.tool {
            extract_bash_command(&input.payload)?
        } else {
            return Err(SandboxError::ExecutionFailed(format!(
                "Enforcement mode (sandbox) is not supported for tool '{}'. Use check mode instead.",
                input.tool.name()
            )));
        };

        let mode = state.engine.effective_mode(&input.tool, &input.context);
        let working_directory = input
            .context
            .working_directory
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("."));

        let ctx = SandboxContext {
            mode,
            working_directory,
            timeout_ms: None,
        };

        state
            .siem_exporter
            .export(agent_guard_core::AuditRecord::ExecutionStarted(
                agent_guard_core::ExecutionEvent {
                    timestamp: chrono::Utc::now(),
                    request_id: request_id.clone(),
                    agent_id: input.context.agent_id.clone(),
                    tool: input.tool.name().to_string(),
                    sandbox_type: sandbox.sandbox_type().to_string(),
                    duration_ms: None,
                    exit_code: None,
                },
            ));

        let start = std::time::Instant::now();
        let execution_res = sandbox.execute(&command, &ctx);
        let duration = start.elapsed();

        let output = match execution_res {
            Ok(out) => out,
            Err(e) => {
                state
                    .siem_exporter
                    .export(agent_guard_core::AuditRecord::SandboxFailure(
                        agent_guard_core::SandboxFailureEvent {
                            timestamp: chrono::Utc::now(),
                            request_id: request_id.clone(),
                            agent_id: input.context.agent_id.clone(),
                            tool: input.tool.name().to_string(),
                            sandbox_type: sandbox.sandbox_type().to_string(),
                            error: e.to_string(),
                        },
                    ));
                return Err(e);
            }
        };

        state
            .siem_exporter
            .export(agent_guard_core::AuditRecord::ExecutionFinished(
                agent_guard_core::ExecutionEvent {
                    timestamp: chrono::Utc::now(),
                    request_id: request_id.clone(),
                    agent_id: input.context.agent_id.clone(),
                    tool: input.tool.name().to_string(),
                    sandbox_type: sandbox.sandbox_type().to_string(),
                    duration_ms: Some(duration.as_millis() as u64),
                    exit_code: Some(output.exit_code),
                },
            ));

        let agent_id = input
            .context
            .agent_id
            .clone()
            .unwrap_or_else(|| "default".to_string());
        crate::metrics::get_metrics()
            .execution_duration_seconds
            .get_or_create(&crate::metrics::ExecutionLabels {
                agent_id: agent_id.clone(),
                tool: input.tool.name().to_string(),
                sandbox_type: sandbox.sandbox_type().to_string(),
            })
            .observe(duration.as_secs_f64());

        let receipt = state.signing_key.as_ref().map(|key| {
            crate::provenance::ExecutionReceipt::sign(
                &agent_id,
                input.tool.name(),
                &policy_version,
                sandbox.sandbox_type(),
                &decision,
                &sha256_hash(&input.payload),
                key,
            )
        });

        Ok(ExecuteOutcome::Executed {
            output,
            policy_version,
            receipt,
        })
    }

    pub fn execute_default(&self, input: &GuardInput) -> ExecuteResult {
        let sandbox = Self::default_sandbox();
        self.execute(input, sandbox.as_ref())
    }

    pub fn default_sandbox() -> Box<dyn Sandbox> {
        #[cfg(target_os = "linux")]
        {
            #[cfg(feature = "landlock")]
            {
                let ll = agent_guard_sandbox::LandlockSandbox;
                if ll.is_available() {
                    return Box::new(ll);
                }
            }
            Box::new(agent_guard_sandbox::SeccompSandbox::new())
        }
        #[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
        {
            let sb = agent_guard_sandbox::SeatbeltSandbox;
            if sb.is_available() {
                Box::new(sb)
            } else {
                Box::new(agent_guard_sandbox::NoopSandbox)
            }
        }
        #[cfg(all(target_os = "windows", feature = "windows-appcontainer"))]
        {
            Box::new(agent_guard_sandbox::AppContainerSandbox)
        }
        #[cfg(all(
            target_os = "windows",
            not(feature = "windows-appcontainer"),
            feature = "windows-sandbox"
        ))]
        {
            Box::new(agent_guard_sandbox::JobObjectSandbox)
        }
        #[cfg(not(any(
            target_os = "linux",
            all(target_os = "macos", feature = "macos-sandbox"),
            all(target_os = "windows", feature = "windows-appcontainer"),
            all(
                target_os = "windows",
                not(feature = "windows-appcontainer"),
                feature = "windows-sandbox"
            )
        )))]
        {
            Box::new(agent_guard_sandbox::NoopSandbox)
        }
    }

    fn evaluate(&self, input: &GuardInput, state: &GuardState) -> GuardDecision {
        if let Tool::Bash = &input.tool {
            let mode = policy_mode_to_permission_mode(
                &state.engine.effective_mode(&input.tool, &input.context),
            );
            let workspace_path: &Path = input
                .context
                .working_directory
                .as_deref()
                .unwrap_or_else(|| Path::new("."));

            let v: serde_json::Value = match serde_json::from_str(&input.payload) {
                Ok(v) => v,
                Err(_) => {
                    return GuardDecision::deny(
                        DecisionCode::InvalidPayload,
                        "invalid payload JSON",
                    )
                }
            };
            let command = match v.get("command").and_then(|c| c.as_str()) {
                Some(s) => s,
                None => {
                    return GuardDecision::deny(
                        DecisionCode::MissingPayloadField,
                        "payload missing 'command' field",
                    )
                }
            };

            let result = validate_bash_command(command, mode, workspace_path);
            match result {
                ValidationResult::Block { reason } => {
                    let code = classify_block_reason(&reason);
                    return GuardDecision::deny(code, reason);
                }
                ValidationResult::Warn { message } => {
                    return GuardDecision::ask(
                        message.clone(),
                        DecisionCode::DestructiveCommand,
                        message,
                    );
                }
                ValidationResult::Allow => {}
            }
        }

        state
            .engine
            .check(&input.tool, &input.payload, &input.context)
    }

    fn write_audit(
        &self,
        input: &GuardInput,
        decision: &GuardDecision,
        state: &GuardState,
        request_id: &str,
    ) {
        let event = AuditEvent::from_decision(
            request_id.to_string(),
            &input.tool,
            &input.payload,
            decision,
            input.context.session_id.clone(),
            input.context.agent_id.clone(),
            input.context.actor.clone(),
            state.audit_cfg.include_payload_hash,
            state.engine.version().to_string(),
        );
        let line = event.to_jsonl();

        state
            .siem_exporter
            .export(agent_guard_core::AuditRecord::ToolCall(event));

        if state.audit_cfg.output == "file" {
            if let Some(ref mutex) = state.audit_file {
                match mutex.lock() {
                    Ok(mut file) => {
                        use std::io::Write;
                        if let Err(e) = writeln!(file, "{}", line) {
                            tracing::error!("Failed to write to audit file: {}", e);
                        }
                    }
                    Err(_) => {
                        tracing::error!("Audit file mutex poisoned");
                    }
                }
            }
        } else {
            println!("{}", line);
        }
    }

    fn write_reload_audit(&self, event: &ReloadEvent, state: &GuardState) {
        let line = event.to_jsonl();
        state
            .siem_exporter
            .export(agent_guard_core::AuditRecord::PolicyReload(event.clone()));

        if state.audit_cfg.enabled && state.audit_cfg.output == "file" {
            if let Some(ref mutex) = state.audit_file {
                match mutex.lock() {
                    Ok(mut file) => {
                        use std::io::Write;
                        if let Err(e) = writeln!(file, "{}", line) {
                            tracing::error!("Failed to write reload event to audit file: {}", e);
                        }
                    }
                    Err(_) => {
                        tracing::error!("Audit file mutex poisoned during reload");
                    }
                }
            }
        }
    }
}

impl GuardState {
    fn new(engine: Arc<PolicyEngine>) -> Result<Self, GuardInitError> {
        let audit_cfg = engine.audit_config().clone();
        let audit_file = if audit_cfg.output == "file" {
            if let Some(ref path) = audit_cfg.file_path {
                let f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| GuardInitError::AuditFileOpen {
                        path: path.clone(),
                        source: e,
                    })?;
                Some(Arc::new(std::sync::Mutex::new(f)))
            } else {
                None
            }
        } else {
            None
        };

        let siem_exporter = Arc::new(SiemExporter::new(audit_cfg.clone()));

        Ok(Self {
            engine,
            audit_cfg,
            audit_file,
            siem_exporter,
            signing_key: None,
        })
    }
}

// ── ExecuteResult ─────────────────────────────────────────────────────────────

pub type ExecuteResult = Result<ExecuteOutcome, SandboxError>;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ExecuteOutcome {
    Executed {
        output: SandboxOutput,
        policy_version: String,
        receipt: Option<crate::provenance::ExecutionReceipt>,
    },
    Denied {
        decision: GuardDecision,
        policy_version: String,
    },
    AskRequired {
        decision: GuardDecision,
        policy_version: String,
    },
}

fn extract_bash_command(payload: &str) -> Result<String, SandboxError> {
    let v: serde_json::Value = serde_json::from_str(payload)
        .map_err(|_| SandboxError::ExecutionFailed("invalid payload JSON".to_string()))?;
    v.get("command")
        .and_then(|c| c.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| SandboxError::ExecutionFailed("payload missing 'command' field".to_string()))
}

fn anomaly_subject(context: &Context) -> String {
    context
        .actor
        .clone()
        .or_else(|| context.agent_id.clone())
        .or_else(|| context.session_id.clone())
        .unwrap_or_else(|| "unknown".to_string())
}

fn policy_mode_to_permission_mode(mode: &PolicyMode) -> PermissionMode {
    match mode {
        PolicyMode::ReadOnly => PermissionMode::ReadOnly,
        PolicyMode::WorkspaceWrite => PermissionMode::WorkspaceWrite,
        PolicyMode::FullAccess => PermissionMode::DangerFullAccess,
        PolicyMode::Blocked => PermissionMode::Blocked,
    }
}

fn classify_block_reason(reason: &str) -> DecisionCode {
    if reason.contains("read-only mode") {
        DecisionCode::WriteInReadOnlyMode
    } else if reason.contains("destructive") {
        DecisionCode::DestructiveCommand
    } else if reason.contains("outside workspace") {
        DecisionCode::PathOutsideWorkspace
    } else {
        DecisionCode::DeniedByRule
    }
}

fn sha256_hash(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

fn parse_hex_signing_key(hex_str: &str) -> Result<ed25519_dalek::SigningKey, GuardInitError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| GuardInitError::SigningKeyLoad(format!("invalid hex: {}", e)))?;
    let seed: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        GuardInitError::SigningKeyLoad(format!(
            "expected 32 bytes (64 hex chars), got {} bytes",
            v.len()
        ))
    })?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}
