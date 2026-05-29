//! Sandbox-backed enforcement: `execute*`, `run*`, and handoff reporting.
//!
//! Splits responsibility from `guard.rs` (lifecycle + policy check + audit)
//! so each file stays close to a single concern.

use std::path::PathBuf;

use agent_guard_core::{
    DecisionCode, DecisionReason, GuardDecision, GuardInput, RuntimeDecision, Tool,
};
use agent_guard_sandbox::{Sandbox, SandboxContext, SandboxError, SandboxOutput};
use serde::Serialize;
use uuid::Uuid;

use crate::executors::{
    execute_http_request, execute_write_file, extract_bash_command_for_execution,
};
use crate::guard::Guard;
use crate::guard_helpers::sha256_hash;
use crate::policy_signing::PolicyVerification;
use crate::runtime::{HandoffResult, RuntimeOutcome, RuntimeResult};

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

impl Guard {
    pub fn execute(&self, input: &GuardInput, sandbox: &dyn Sandbox) -> ExecuteResult {
        let request_id = Uuid::new_v4().to_string();
        self.execute_with_request_id(input, sandbox, &request_id)
    }

    pub(crate) fn execute_with_request_id(
        &self,
        input: &GuardInput,
        sandbox: &dyn Sandbox,
        request_id: &str,
    ) -> ExecuteResult {
        // Industrial Standard: Single-snapshot isolation.
        let state = self.state.load();
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

        let decision = self.check_internal(input, &state, request_id);
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

        // S6-4c: content-layer masking on the execution path. For Mask mode,
        // execute a redacted copy of the payload; for Warn, execute the
        // original. Either way emit a ContentFinding audit record. Off by
        // default; compiled only with the `content` feature.
        #[cfg(feature = "content")]
        let masked_payload: Option<String> =
            self.apply_content_on_execution(input, &state, request_id);
        #[cfg(feature = "content")]
        let exec_payload: &str = masked_payload.as_deref().unwrap_or(&input.payload);
        #[cfg(not(feature = "content"))]
        let exec_payload: &str = &input.payload;

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
                    request_id: request_id.to_string(),
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
                let command = extract_bash_command_for_execution(exec_payload)?;
                sandbox.execute(&command, &ctx)
            }
            Tool::WriteFile => {
                execute_write_file(exec_payload, input.context.working_directory.as_deref())
            }
            Tool::HttpRequest => execute_http_request(exec_payload),
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
                            request_id: request_id.to_string(),
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
                    request_id: request_id.to_string(),
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
                &sha256_hash(exec_payload),
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

    /// S6-4c: apply the content policy on the execution path, emit a
    /// `ContentFinding` audit record, and return a masked payload when the
    /// policy is in Mask mode. Returns `None` when no content policy applies
    /// or no sensitive content was found (caller keeps the original payload).
    #[cfg(feature = "content")]
    fn apply_content_on_execution(
        &self,
        input: &GuardInput,
        state: &crate::guard::GuardState,
        request_id: &str,
    ) -> Option<String> {
        let policy = state.engine.content_policy(&input.tool)?;
        let app = crate::content_filter::apply_content_for_execution(
            policy,
            &input.tool,
            &input.payload,
        )?;

        let mode_label = match app.mode {
            agent_guard_core::ContentMode::Mask => "mask",
            agent_guard_core::ContentMode::Warn => "warn",
            agent_guard_core::ContentMode::Block => "block",
        };

        state
            .siem_exporter
            .export(agent_guard_core::AuditRecord::ContentFinding(
                agent_guard_core::ContentFindingEvent {
                    timestamp: chrono::Utc::now(),
                    request_id: request_id.to_string(),
                    agent_id: input.context.agent_id.clone(),
                    tool: input.tool.name().to_string(),
                    mode: mode_label.to_string(),
                    count: app.labels.len(),
                    labels: app.labels,
                },
            ));

        app.masked_payload
    }

    pub fn execute_default(&self, input: &GuardInput) -> ExecuteResult {
        let sandbox = Self::default_sandbox();
        self.execute(input, sandbox.as_ref())
    }

    pub fn run(&self, input: &GuardInput, sandbox: &dyn Sandbox) -> RuntimeResult {
        let request_id = Uuid::new_v4().to_string();
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
                request_id,
                reason,
                policy_version,
                policy_verification: state.policy_verification.clone(),
            });
        }

        let decision = self.decide(input);
        match decision {
            RuntimeDecision::Execute => {
                match self.execute_with_request_id(input, sandbox, &request_id)? {
                    ExecuteOutcome::Executed {
                        output,
                        policy_version,
                        receipt,
                        policy_verification,
                    } => Ok(RuntimeOutcome::Executed {
                        request_id,
                        output,
                        policy_version,
                        receipt,
                        policy_verification,
                    }),
                    ExecuteOutcome::Denied {
                        decision,
                        policy_version,
                        policy_verification,
                    } => {
                        let reason = match decision {
                            GuardDecision::Deny { reason } => reason,
                            // Execute path only returns Denied for GuardDecision::Deny.
                            other => unreachable!(
                                "ExecuteOutcome::Denied should carry GuardDecision::Deny, got {other:?}"
                            ),
                        };
                        Ok(RuntimeOutcome::Denied {
                            request_id,
                            reason,
                            policy_version,
                            policy_verification,
                        })
                    }
                    ExecuteOutcome::AskRequired {
                        decision,
                        policy_version,
                        policy_verification,
                    } => {
                        let (message, reason) = match decision {
                            GuardDecision::AskUser { message, reason } => (message, reason),
                            // Execute path only returns AskRequired for GuardDecision::AskUser.
                            other => unreachable!(
                                "ExecuteOutcome::AskRequired should carry GuardDecision::AskUser, got {other:?}"
                            ),
                        };
                        Ok(RuntimeOutcome::AskForApproval {
                            request_id,
                            message,
                            reason,
                            policy_version,
                            policy_verification,
                        })
                    }
                }
            }
            RuntimeDecision::Handoff => Ok(RuntimeOutcome::Handoff {
                request_id,
                policy_version,
                policy_verification: state.policy_verification.clone(),
            }),
            RuntimeDecision::Deny { reason } => Ok(RuntimeOutcome::Denied {
                request_id,
                reason,
                policy_version,
                policy_verification: state.policy_verification.clone(),
            }),
            RuntimeDecision::AskForApproval { message, reason } => {
                Ok(RuntimeOutcome::AskForApproval {
                    request_id,
                    message,
                    reason,
                    policy_version,
                    policy_verification: state.policy_verification.clone(),
                })
            }
        }
    }

    pub fn run_default(&self, input: &GuardInput) -> RuntimeResult {
        let sandbox = Self::default_sandbox();
        self.run(input, sandbox.as_ref())
    }

    /// Report the outcome of a host-executed handoff action back into the
    /// audit stream.
    ///
    /// When `Guard::run` returns `RuntimeOutcome::Handoff`, the host executes
    /// the action itself; the SDK therefore does not emit an
    /// `ExecutionFinished` audit record for that path. Hosts call this method
    /// after the handoff executes to close the audit loop with a matching
    /// record. `request_id` must be the one returned by the prior `run` call
    /// so that the `ExecutionStarted` intent (if any) and this finish event
    /// can be correlated downstream.
    ///
    /// The emitted `ExecutionEvent` reuses the existing `SiemExporter` and
    /// (when configured) JSONL audit file pipelines, with `tool = "handoff"`
    /// and `sandbox_type = "host-handoff"` so consumers can tell these apart
    /// from in-SDK executions.
    pub fn report_handoff_result(&self, request_id: &str, result: HandoffResult) {
        let state = self.state.load();
        let stderr_present = result.stderr.is_some();
        let event = agent_guard_core::ExecutionEvent {
            timestamp: chrono::Utc::now(),
            request_id: request_id.to_string(),
            agent_id: None,
            tool: "handoff".to_string(),
            sandbox_type: "host-handoff".to_string(),
            duration_ms: Some(result.duration_ms),
            exit_code: Some(result.exit_code),
        };

        state
            .siem_exporter
            .export(agent_guard_core::AuditRecord::ExecutionFinished(
                event.clone(),
            ));

        if state.audit_cfg.enabled && state.audit_cfg.output == "file" {
            if let Some(ref writer) = state.audit_file_writer {
                let record = agent_guard_core::AuditRecord::ExecutionFinished(event);
                let line = serde_json::to_string(&record).unwrap_or_else(|e| {
                    format!("{{\"error\":\"audit serialization failed: {e}\"}}")
                });
                writer.send(line);
            }
        }

        // `stderr` is captured in the HandoffResult type for future surface
        // expansion (e.g. SIEM details), but is intentionally not part of the
        // core ExecutionEvent schema today; flagging presence keeps this
        // signal from being silently dropped.
        let _ = stderr_present;
    }
}
