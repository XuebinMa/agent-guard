use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agent_guard_core::{
    AuditConfig, AuditEvent, Context, DecisionCode, DecisionReason, GuardDecision, GuardInput,
    PolicyEngine, PolicyMode, ReloadEvent, RuntimeDecision, Tool,
};
use agent_guard_sandbox::{Sandbox, SandboxContext, SandboxError, SandboxOutput};
use agent_guard_validators::bash::{validate_bash_command, PermissionMode, ValidationResult};
use arc_swap::ArcSwap;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use crate::policy_signing::{
    load_policy_signature_file, load_public_key_file, parse_hex_signing_key, verify_policy,
    PolicyVerification,
};
pub use crate::runtime::{RuntimeOutcome, RuntimeResult};
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

#[derive(Debug, Clone, Serialize)]
pub struct DefaultSandboxDiagnosis {
    pub selected_name: &'static str,
    pub selected_sandbox_type: &'static str,
    pub fallback_to_noop: bool,
    pub reason: String,
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
    anomaly_detector: Arc<crate::anomaly::AnomalyDetector>,
    signing_key: Option<ed25519_dalek::SigningKey>,
    policy_verification: PolicyVerification,
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
        let state = GuardState::new(Arc::new(engine), PolicyVerification::unsigned())?;
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

    /// Construct a Guard from a YAML string and detached Ed25519 signature.
    pub fn from_signed_yaml(
        yaml: &str,
        public_key_hex: &str,
        signature_hex: &str,
    ) -> Result<Self, GuardInitError> {
        let engine = PolicyEngine::from_yaml_str(yaml)?;
        Self::new_with_verification(engine, verify_policy(yaml, public_key_hex, signature_hex))
    }

    /// Construct a Guard from a YAML file and detached Ed25519 signature file.
    pub fn from_signed_yaml_file(
        policy_path: impl AsRef<Path>,
        public_key_path: impl AsRef<Path>,
        signature_path: impl AsRef<Path>,
    ) -> Result<Self, GuardInitError> {
        let yaml = std::fs::read_to_string(policy_path)
            .map_err(|error| GuardInitError::SigningKeyLoad(error.to_string()))?;
        let public_key_hex =
            load_public_key_file(public_key_path).map_err(GuardInitError::SigningKeyLoad)?;
        let signature_hex =
            load_policy_signature_file(signature_path).map_err(GuardInitError::SigningKeyLoad)?;
        Self::from_signed_yaml(&yaml, &public_key_hex, &signature_hex)
    }

    fn new_with_verification(
        engine: PolicyEngine,
        policy_verification: PolicyVerification,
    ) -> Result<Self, GuardInitError> {
        let state = GuardState::new(Arc::new(engine), policy_verification)?;
        Ok(Self {
            state: ArcSwap::from_pointee(state),
        })
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
        let key = parse_hex_signing_key(hex_str.trim()).map_err(GuardInitError::SigningKeyLoad)?;
        self.with_signing_key(key);
        Ok(())
    }

    /// Atomically reload the policy engine from a new instance.
    pub fn reload_engine(&self, engine: PolicyEngine) -> Result<(), GuardInitError> {
        self.reload_engine_with_verification(engine, PolicyVerification::unsigned())
    }

    pub fn reload_engine_with_verification(
        &self,
        engine: PolicyEngine,
        policy_verification: PolicyVerification,
    ) -> Result<(), GuardInitError> {
        let old_state = self.state.load();
        let old_version = old_state.engine.version().to_string();
        let new_version = engine.version().to_string();

        let mut new_state = GuardState::new(Arc::new(engine), policy_verification)?;
        new_state.anomaly_detector = old_state.anomaly_detector.clone();
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

    pub fn reload_from_signed_yaml(
        &self,
        yaml: &str,
        public_key_hex: &str,
        signature_hex: &str,
    ) -> Result<(), GuardInitError> {
        match PolicyEngine::from_yaml_str(yaml) {
            Ok(engine) => self.reload_engine_with_verification(
                engine,
                verify_policy(yaml, public_key_hex, signature_hex),
            ),
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

    pub fn reload_from_signed_yaml_file(
        &self,
        policy_path: impl AsRef<Path>,
        public_key_path: impl AsRef<Path>,
        signature_path: impl AsRef<Path>,
    ) -> Result<(), GuardInitError> {
        let yaml = std::fs::read_to_string(policy_path)
            .map_err(|error| GuardInitError::SigningKeyLoad(error.to_string()))?;
        let public_key_hex =
            load_public_key_file(public_key_path).map_err(GuardInitError::SigningKeyLoad)?;
        let signature_hex =
            load_policy_signature_file(signature_path).map_err(GuardInitError::SigningKeyLoad)?;
        self.reload_from_signed_yaml(&yaml, &public_key_hex, &signature_hex)
    }

    /// Return the current policy version (alias for version)
    pub fn policy_version(&self) -> String {
        self.state.load().engine.version().to_string()
    }

    /// Return the SHA-256 hash of the currently loaded policy.
    pub fn policy_hash(&self) -> String {
        self.state.load().engine.hash().to_string()
    }

    pub fn policy_verification(&self) -> PolicyVerification {
        self.state.load().policy_verification.clone()
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

    pub fn decide(&self, input: &GuardInput) -> RuntimeDecision {
        let state = self.state.load();
        let request_id = Uuid::new_v4().to_string();
        let decision = self.check_internal(input, &state, &request_id);
        runtime_decision_for_input(input, decision)
    }

    pub fn decide_tool(
        &self,
        tool: Tool,
        payload: impl Into<String>,
        context: Context,
    ) -> RuntimeDecision {
        let input = GuardInput {
            tool,
            payload: payload.into(),
            context,
        };
        self.decide(&input)
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

        match state.anomaly_detector.check(&anomaly_subject, anomaly_cfg) {
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
                state
                    .anomaly_detector
                    .report_denial(&anomaly_subject, anomaly_cfg);
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

        if state.policy_verification.should_fail_closed() {
            let mut reason = DecisionReason::new(
                DecisionCode::PolicyVerificationFailed,
                "policy signature verification failed; enforce mode is blocked until the policy is verified",
            );
            let mut details = serde_json::Map::new();
            details.insert(
                "policy_verification_status".to_string(),
                serde_json::Value::String(state.policy_verification.status_label().to_string()),
            );
            if let Some(error) = &state.policy_verification.error {
                details.insert(
                    "policy_verification_error".to_string(),
                    serde_json::Value::String(error.clone()),
                );
            }
            reason.details = Some(serde_json::Value::Object(details));
            return Ok(ExecuteOutcome::Denied {
                decision: GuardDecision::Deny { reason },
                policy_version,
                policy_verification: state.policy_verification.clone(),
            });
        }

        let decision = self.check_internal(input, &state, &request_id);
        match &decision {
            GuardDecision::Allow => {}
            GuardDecision::Deny { .. } => {
                return Ok(ExecuteOutcome::Denied {
                    decision,
                    policy_version,
                    policy_verification: state.policy_verification.clone(),
                });
            }
            GuardDecision::AskUser { .. } => {
                return Ok(ExecuteOutcome::AskRequired {
                    decision,
                    policy_version,
                    policy_verification: state.policy_verification.clone(),
                });
            }
        }

        let mode = state.engine.effective_mode(&input.tool, &input.context);
        let working_directory = input
            .context
            .working_directory
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));

        let ctx = SandboxContext {
            mode,
            working_directory,
            timeout_ms: None,
        };

        let execution_backend = match input.tool {
            Tool::Bash => sandbox.sandbox_type().to_string(),
            Tool::WriteFile => "builtin-file-write".to_string(),
            Tool::HttpRequest => "builtin-http-request".to_string(),
            _ => {
                return Err(SandboxError::ExecutionFailed(format!(
                    "Enforcement mode (sandbox) is not supported for tool '{}'. Use check mode instead.",
                    input.tool.name()
                )));
            }
        };

        state
            .siem_exporter
            .export(agent_guard_core::AuditRecord::ExecutionStarted(
                agent_guard_core::ExecutionEvent {
                    timestamp: chrono::Utc::now(),
                    request_id: request_id.clone(),
                    agent_id: input.context.agent_id.clone(),
                    tool: input.tool.name().to_string(),
                    sandbox_type: execution_backend.clone(),
                    duration_ms: None,
                    exit_code: None,
                },
            ));

        let start = std::time::Instant::now();
        let execution_res = match input.tool {
            Tool::Bash => {
                let command = extract_bash_command(&input.payload)?;
                sandbox.execute(&command, &ctx)
            }
            Tool::WriteFile => execute_write_file(&input.payload),
            Tool::HttpRequest => execute_http_request(&input.payload),
            _ => unreachable!("unsupported tool already returned above"),
        };
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
                            sandbox_type: execution_backend.clone(),
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
                    sandbox_type: execution_backend.clone(),
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
                sandbox_type: execution_backend.clone(),
            })
            .observe(duration.as_secs_f64());

        let receipt = state.signing_key.as_ref().map(|key| {
            crate::provenance::ExecutionReceipt::sign(
                &agent_id,
                input.tool.name(),
                &policy_version,
                &execution_backend,
                &decision,
                &sha256_hash(&input.payload),
                key,
            )
        });

        Ok(ExecuteOutcome::Executed {
            output,
            policy_version,
            receipt,
            policy_verification: state.policy_verification.clone(),
        })
    }

    pub fn execute_default(&self, input: &GuardInput) -> ExecuteResult {
        let sandbox = Self::default_sandbox();
        self.execute(input, sandbox.as_ref())
    }

    pub fn run(&self, input: &GuardInput, sandbox: &dyn Sandbox) -> RuntimeResult {
        let state = self.state.load();
        let policy_version = state.engine.version().to_string();

        if state.policy_verification.should_fail_closed() {
            let mut reason = DecisionReason::new(
                DecisionCode::PolicyVerificationFailed,
                "policy signature verification failed; runtime execution is blocked until the policy is verified",
            );
            let mut details = serde_json::Map::new();
            details.insert(
                "policy_verification_status".to_string(),
                serde_json::Value::String(state.policy_verification.status_label().to_string()),
            );
            if let Some(error) = &state.policy_verification.error {
                details.insert(
                    "policy_verification_error".to_string(),
                    serde_json::Value::String(error.clone()),
                );
            }
            reason.details = Some(serde_json::Value::Object(details));
            return Ok(RuntimeOutcome::Denied {
                decision: RuntimeDecision::Deny { reason },
                policy_version,
                policy_verification: state.policy_verification.clone(),
            });
        }

        let decision = self.decide(input);
        match decision.clone() {
            RuntimeDecision::Execute => match self.execute(input, sandbox)? {
                ExecuteOutcome::Executed {
                    output,
                    policy_version,
                    receipt,
                    policy_verification,
                } => Ok(RuntimeOutcome::Executed {
                    output,
                    policy_version,
                    receipt,
                    policy_verification,
                }),
                ExecuteOutcome::Denied {
                    decision,
                    policy_version,
                    policy_verification,
                } => Ok(RuntimeOutcome::Denied {
                    decision: runtime_decision_for_input(input, decision),
                    policy_version,
                    policy_verification,
                }),
                ExecuteOutcome::AskRequired {
                    decision,
                    policy_version,
                    policy_verification,
                } => Ok(RuntimeOutcome::AskForApproval {
                    decision: runtime_decision_for_input(input, decision),
                    policy_version,
                    policy_verification,
                }),
            },
            RuntimeDecision::Handoff => Ok(RuntimeOutcome::Handoff {
                decision,
                policy_version,
                policy_verification: state.policy_verification.clone(),
            }),
            RuntimeDecision::Deny { .. } => Ok(RuntimeOutcome::Denied {
                decision,
                policy_version,
                policy_verification: state.policy_verification.clone(),
            }),
            RuntimeDecision::AskForApproval { .. } => Ok(RuntimeOutcome::AskForApproval {
                decision,
                policy_version,
                policy_verification: state.policy_verification.clone(),
            }),
        }
    }

    pub fn run_default(&self, input: &GuardInput) -> RuntimeResult {
        let sandbox = Self::default_sandbox();
        self.run(input, sandbox.as_ref())
    }

    pub fn default_sandbox() -> Box<dyn Sandbox> {
        Self::resolve_default_sandbox().0
    }

    pub fn default_sandbox_diagnosis() -> DefaultSandboxDiagnosis {
        Self::resolve_default_sandbox().1
    }

    fn resolve_default_sandbox() -> (Box<dyn Sandbox>, DefaultSandboxDiagnosis) {
        #[cfg(target_os = "linux")]
        {
            #[cfg(feature = "landlock")]
            {
                let ll = agent_guard_sandbox::LandlockSandbox;
                if ll.is_available() {
                    return (
                        Box::new(ll),
                        DefaultSandboxDiagnosis {
                            selected_name: "landlock",
                            selected_sandbox_type: "linux-landlock",
                            fallback_to_noop: false,
                            reason: "Landlock is functional on this Linux host, so the SDK selects the stricter workspace-write backend.".to_string(),
                        },
                    );
                }
            }
            (
                Box::new(agent_guard_sandbox::SeccompSandbox::new()),
                DefaultSandboxDiagnosis {
                    selected_name: "seccomp",
                    selected_sandbox_type: "linux-seccomp",
                    fallback_to_noop: false,
                    reason: "Linux defaults to seccomp; Landlock is either disabled or unavailable on this host.".to_string(),
                },
            )
        }
        #[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
        {
            let sb = agent_guard_sandbox::SeatbeltSandbox;
            if sb.is_available() {
                (
                    Box::new(sb),
                    DefaultSandboxDiagnosis {
                        selected_name: "seatbelt",
                        selected_sandbox_type: "macos-seatbelt",
                        fallback_to_noop: false,
                        reason: "Seatbelt runtime checks passed, so macOS execution uses the native sandbox backend.".to_string(),
                    },
                )
            } else {
                (
                    Box::new(agent_guard_sandbox::NoopSandbox),
                    DefaultSandboxDiagnosis {
                        selected_name: "none",
                        selected_sandbox_type: "none",
                        fallback_to_noop: true,
                        reason: "Seatbelt support is enabled, but sandbox-exec is not functional on this host, so the SDK falls back to NoopSandbox.".to_string(),
                    },
                )
            }
        }
        #[cfg(all(target_os = "windows", feature = "windows-appcontainer"))]
        {
            (
                Box::new(agent_guard_sandbox::AppContainerSandbox),
                DefaultSandboxDiagnosis {
                    selected_name: "AppContainer",
                    selected_sandbox_type: "windows-appcontainer",
                    fallback_to_noop: false,
                    reason: "The windows-appcontainer feature is enabled, so the SDK prefers AppContainer as the default Windows backend.".to_string(),
                },
            )
        }
        #[cfg(all(
            target_os = "windows",
            not(feature = "windows-appcontainer"),
            feature = "windows-sandbox"
        ))]
        {
            let sb = agent_guard_sandbox::JobObjectSandbox;
            if sb.is_available() {
                (
                    Box::new(sb),
                    DefaultSandboxDiagnosis {
                        selected_name: "JobObject",
                        selected_sandbox_type: "windows-job-object",
                        fallback_to_noop: false,
                        reason: "Low-integrity process creation is functional on this Windows host, so the SDK uses the Job Object backend.".to_string(),
                    },
                )
            } else {
                (
                    Box::new(agent_guard_sandbox::NoopSandbox),
                    DefaultSandboxDiagnosis {
                        selected_name: "none",
                        selected_sandbox_type: "none",
                        fallback_to_noop: true,
                        reason: "The Windows low-integrity runtime is unavailable on this host, so the SDK falls back to NoopSandbox instead of pretending enforcement is active.".to_string(),
                    },
                )
            }
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
            (
                Box::new(agent_guard_sandbox::NoopSandbox),
                DefaultSandboxDiagnosis {
                    selected_name: "none",
                    selected_sandbox_type: "none",
                    fallback_to_noop: true,
                    reason: "No OS-level sandbox backend is enabled for this platform/build, so the SDK uses NoopSandbox.".to_string(),
                },
            )
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
        if !state.audit_cfg.enabled {
            return;
        }

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
    fn new(
        engine: Arc<PolicyEngine>,
        policy_verification: PolicyVerification,
    ) -> Result<Self, GuardInitError> {
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
        let anomaly_detector = Arc::new(crate::anomaly::AnomalyDetector::new());

        Ok(Self {
            engine,
            audit_cfg,
            audit_file,
            siem_exporter,
            anomaly_detector,
            signing_key: None,
            policy_verification,
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
        policy_verification: PolicyVerification,
    },
    Denied {
        decision: GuardDecision,
        policy_version: String,
        policy_verification: PolicyVerification,
    },
    AskRequired {
        decision: GuardDecision,
        policy_version: String,
        policy_verification: PolicyVerification,
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

#[derive(Debug, Deserialize)]
struct WriteFileRequest {
    path: String,
    content: String,
    #[serde(default)]
    append: bool,
}

fn execute_write_file(payload: &str) -> Result<SandboxOutput, SandboxError> {
    let request: WriteFileRequest = serde_json::from_str(payload)
        .map_err(|_| SandboxError::ExecutionFailed("invalid payload JSON".to_string()))?;

    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true);
    if request.append {
        options.append(true);
    } else {
        options.truncate(true);
    }

    let mut file = options
        .open(&request.path)
        .map_err(|e| SandboxError::ExecutionFailed(format!("failed to open file for write: {e}")))?;
    file.write_all(request.content.as_bytes())
        .map_err(|e| SandboxError::ExecutionFailed(format!("failed to write file content: {e}")))?;

    Ok(SandboxOutput {
        exit_code: 0,
        stdout: String::new(),
        stderr: String::new(),
    })
}

#[derive(Debug, Deserialize)]
struct HttpRequestExecution {
    method: Option<String>,
    url: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    body: Option<String>,
}

fn execute_http_request(payload: &str) -> Result<SandboxOutput, SandboxError> {
    let request: HttpRequestExecution = serde_json::from_str(payload)
        .map_err(|_| SandboxError::ExecutionFailed("invalid payload JSON".to_string()))?;

    let handle = std::thread::spawn(move || {
        let method = request
            .method
            .as_deref()
            .unwrap_or("GET")
            .parse::<reqwest::Method>()
            .map_err(|e| SandboxError::ExecutionFailed(format!("invalid HTTP method: {e}")))?;

        if !is_mutation_method(&method) {
            return Err(SandboxError::ExecutionFailed(format!(
                "HTTP method '{}' is not supported for owned execution; use mutation methods only",
                method
            )));
        }

        let client = reqwest::blocking::Client::builder().build().map_err(|e| {
            SandboxError::ExecutionFailed(format!("failed to build HTTP client: {e}"))
        })?;

        let mut builder = client.request(method, &request.url);
        for (name, value) in request.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }

        let response = builder
            .send()
            .map_err(|e| SandboxError::ExecutionFailed(format!("HTTP request failed: {e}")))?;
        let status = response.status();
        let body = response.text().map_err(|e| {
            SandboxError::ExecutionFailed(format!("failed to read HTTP response body: {e}"))
        })?;

        Ok(SandboxOutput {
            exit_code: if status.is_success() { 0 } else { 1 },
            stdout: body,
            stderr: String::new(),
        })
    });

    handle
        .join()
        .map_err(|_| SandboxError::ExecutionFailed("HTTP execution thread panicked".to_string()))?
}

fn runtime_decision_for_input(input: &GuardInput, decision: GuardDecision) -> RuntimeDecision {
    match decision {
        GuardDecision::Allow => {
            if matches!(input.tool, Tool::Bash | Tool::WriteFile) {
                RuntimeDecision::Execute
            } else if matches!(input.tool, Tool::HttpRequest)
                && payload_declares_mutation_http(&input.payload)
            {
                RuntimeDecision::Execute
            } else {
                RuntimeDecision::Handoff
            }
        }
        GuardDecision::Deny { reason } => RuntimeDecision::Deny { reason },
        GuardDecision::AskUser { message, reason } => {
            RuntimeDecision::AskForApproval { message, reason }
        }
    }
}

fn payload_declares_mutation_http(payload: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(payload)
        .ok()
        .and_then(|v| {
            v.get("method")
                .and_then(|m| m.as_str())
                .map(|s| s.to_ascii_uppercase())
        })
        .map(|method| matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE"))
        .unwrap_or(false)
}

fn is_mutation_method(method: &reqwest::Method) -> bool {
    matches!(
        *method,
        reqwest::Method::POST
            | reqwest::Method::PUT
            | reqwest::Method::PATCH
            | reqwest::Method::DELETE
    )
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
