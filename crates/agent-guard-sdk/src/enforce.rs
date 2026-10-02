//! Sandbox-backed enforcement: `execute*`, `run*`, and handoff reporting.
//!
//! Splits responsibility from `guard.rs` (lifecycle + policy check + audit)
//! so each file stays close to a single concern.

use std::path::PathBuf;
use std::time::Instant;

use agent_guard_core::{
    DecisionCode, DecisionReason, GuardDecision, GuardInput, PolicyMode, RuntimeDecision, Tool,
};
use agent_guard_sandbox::{Sandbox, SandboxContext, SandboxError, SandboxOutput};
use serde::Serialize;

use crate::approval::{ApprovalConfig, ApprovalError, ApprovalRecord, ApprovalStatus};
use crate::executors::{
    execute_http_request, execute_write_file, extract_bash_command_for_execution, WriteFileScope,
};
use crate::guard::Guard;
use crate::guard_helpers::sha256_hash;
use crate::policy_signing::PolicyVerification;
use crate::provenance::ApprovalProof;
use crate::runtime::{RuntimeOutcome, RuntimeResult};

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
        let evaluated = self.evaluate_request(input);
        self.execute_evaluated(input, sandbox, evaluated)
    }

    fn execute_evaluated(
        &self,
        input: &GuardInput,
        sandbox: &dyn Sandbox,
        evaluated: crate::guard::EvaluatedRequest,
    ) -> ExecuteResult {
        let decision = evaluated.evaluated.decision.clone();
        match &decision {
            GuardDecision::Allow => {}
            GuardDecision::Deny { .. } => {
                return Ok(ExecuteOutcome::Denied {
                    decision,
                    policy_version: evaluated.policy_version,
                    policy_verification: evaluated.policy_verification,
                });
            }
            GuardDecision::AskUser { .. } => {
                return Ok(ExecuteOutcome::AskRequired {
                    decision,
                    policy_version: evaluated.policy_version,
                    policy_verification: evaluated.policy_verification,
                });
            }
            // Fail closed: an unrecognized decision kind must never execute.
            _ => {
                return Ok(ExecuteOutcome::Denied {
                    decision,
                    policy_version: evaluated.policy_version,
                    policy_verification: evaluated.policy_verification,
                });
            }
        }

        self.execute_allowed(
            input,
            sandbox,
            &evaluated.request_id,
            &evaluated.state,
            evaluated.policy_version,
            &decision,
            None,
        )
    }

    /// Execute an action whose decision has already resolved to "proceed" — a
    /// policy `Allow`, or an `ask` that the approval-resume path has just
    /// revalidated (S7-4). This helper does not itself re-run policy; callers
    /// must pass the same state snapshot used for their final decision.
    #[allow(clippy::too_many_arguments)]
    fn execute_allowed(
        &self,
        input: &GuardInput,
        sandbox: &dyn Sandbox,
        request_id: &str,
        state: &crate::guard::GuardState,
        policy_version: String,
        decision: &GuardDecision,
        approval: Option<ApprovalProof>,
    ) -> ExecuteResult {
        // S6-4c: content-layer masking on the execution path. For Mask mode,
        // execute a redacted copy of the payload; for Warn, execute the
        // original. Either way emit a ContentFinding audit record. Off by
        // default; compiled only with the `content` feature.
        #[cfg(feature = "content")]
        let masked_payload: Option<String> =
            self.apply_content_on_execution(input, state, request_id);
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
            mode: mode.clone(),
            working_directory,
            timeout_ms: Some(state.execution_timeout_ms.get()),
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

        self.emit_record(
            state,
            agent_guard_core::AuditRecord::ExecutionStarted(agent_guard_core::ExecutionEvent {
                timestamp: chrono::Utc::now(),
                request_id: request_id.to_string(),
                agent_id: input.context.agent_id.clone(),
                tool: input.tool.name().to_string(),
                sandbox_type: execution_backend.clone(),
                duration_ms: None,
                exit_code: None,
                // Witnessed by the Guard; there is no host claim to back.
                host_attestation: None,
            }),
        );

        let start = std::time::Instant::now();
        let execution_res = match input.tool {
            Tool::Bash => {
                let command = extract_bash_command_for_execution(exec_payload)?;
                sandbox.execute(&command, &ctx)
            }
            Tool::WriteFile => {
                let scope = match mode {
                    PolicyMode::WorkspaceWrite => {
                        let workspace =
                            input.context.working_directory.as_deref().ok_or_else(|| {
                                SandboxError::InvalidPayload {
                                    code: DecisionCode::InvalidPayload,
                                    message: "working_directory is required for WriteFile in workspace_write mode"
                                        .to_string(),
                                }
                            })?;
                        WriteFileScope::Workspace(workspace)
                    }
                    PolicyMode::FullAccess => WriteFileScope::Unrestricted,
                    PolicyMode::ReadOnly | PolicyMode::Blocked => {
                        return Err(SandboxError::ExecutionFailed(
                            "WriteFile execution reached a non-writable policy mode".to_string(),
                        ));
                    }
                };
                execute_write_file(exec_payload, scope)
            }
            Tool::HttpRequest => execute_http_request(exec_payload),
            _ => unreachable!("unsupported tool already returned above"),
        };
        let duration = start.elapsed();

        let output = match execution_res {
            Ok(out) => out,
            Err(e) => {
                self.emit_record(
                    state,
                    agent_guard_core::AuditRecord::SandboxFailure(
                        agent_guard_core::SandboxFailureEvent {
                            timestamp: chrono::Utc::now(),
                            request_id: request_id.to_string(),
                            agent_id: input.context.agent_id.clone(),
                            tool: input.tool.name().to_string(),
                            sandbox_type: execution_backend.clone(),
                            error: e.to_string(),
                        },
                    ),
                );
                return Err(e);
            }
        };

        self.emit_record(
            state,
            agent_guard_core::AuditRecord::ExecutionFinished(agent_guard_core::ExecutionEvent {
                timestamp: chrono::Utc::now(),
                request_id: request_id.to_string(),
                agent_id: input.context.agent_id.clone(),
                tool: input.tool.name().to_string(),
                sandbox_type: execution_backend.clone(),
                duration_ms: Some(duration.as_millis() as u64),
                exit_code: Some(output.exit_code),
                // Witnessed by the Guard; there is no host claim to back.
                host_attestation: None,
            }),
        );

        let agent_id = input
            .context
            .agent_id
            .clone()
            .unwrap_or_else(|| "default".to_string());
        state
            .metrics
            .execution_duration_seconds
            .get_or_create(&crate::metrics::ExecutionLabels {
                agent_id: agent_id.clone(),
                tool: input.tool.name().to_string(),
                sandbox_type: execution_backend.clone(),
            })
            .observe(duration.as_secs_f64());

        let receipt = state.signing_key.as_ref().map(|key| {
            let receipt = crate::provenance::ExecutionReceipt::sign(
                &agent_id,
                input.tool.name(),
                &policy_version,
                &execution_backend,
                decision,
                &sha256_hash(exec_payload),
                key,
            );
            match &approval {
                Some(proof) => receipt.with_approval(proof.clone(), key),
                None => receipt,
            }
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

        self.emit_record(
            state,
            agent_guard_core::AuditRecord::ContentFinding(agent_guard_core::ContentFindingEvent {
                timestamp: chrono::Utc::now(),
                request_id: request_id.to_string(),
                agent_id: input.context.agent_id.clone(),
                tool: input.tool.name().to_string(),
                mode: mode_label.to_string(),
                count: app.labels.len(),
                labels: app.labels,
            }),
        );

        app.masked_payload
    }

    pub fn execute_default(&self, input: &GuardInput) -> ExecuteResult {
        let sandbox = Self::default_sandbox();
        self.execute(input, sandbox.as_ref())
    }

    pub fn run(&self, input: &GuardInput, sandbox: &dyn Sandbox) -> RuntimeResult {
        let evaluated = self.evaluate_request(input);
        let request_id = evaluated.request_id.clone();
        let policy_version = evaluated.policy_version.clone();
        let policy_verification = evaluated.policy_verification.clone();
        match evaluated.runtime_decision.clone() {
            RuntimeDecision::Execute => {
                match self.execute_allowed(
                    input,
                    sandbox,
                    &request_id,
                    &evaluated.state,
                    policy_version,
                    &evaluated.evaluated.decision,
                    None,
                )? {
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
                            GuardDecision::AskUser {
                                message, reason, ..
                            } => (message, reason),
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
            RuntimeDecision::Handoff => {
                if evaluated.state.audit_cfg.enabled {
                    self.register_handoff(
                        &request_id,
                        std::sync::Arc::clone(&evaluated.state),
                        input,
                    )?;
                    self.emit_record(
                        &evaluated.state,
                        agent_guard_core::AuditRecord::ExecutionStarted(
                            agent_guard_core::ExecutionEvent {
                                timestamp: chrono::Utc::now(),
                                request_id: request_id.clone(),
                                agent_id: input.context.agent_id.clone(),
                                tool: input.tool.name().to_string(),
                                sandbox_type: "host-handoff".to_string(),
                                duration_ms: None,
                                exit_code: None,
                                host_attestation: None,
                            },
                        ),
                    );
                }
                Ok(RuntimeOutcome::Handoff {
                    request_id,
                    policy_version,
                    policy_verification,
                })
            }
            RuntimeDecision::Deny { reason } => Ok(RuntimeOutcome::Denied {
                request_id,
                reason,
                policy_version,
                policy_verification,
            }),
            RuntimeDecision::AskForApproval {
                message, reason, ..
            } => Ok(RuntimeOutcome::AskForApproval {
                request_id,
                message,
                reason,
                policy_version,
                policy_verification,
            }),
            // Fail closed: an unrecognized runtime disposition is denied.
            _ => Ok(RuntimeOutcome::Denied {
                request_id,
                reason: DecisionReason::new(
                    DecisionCode::InternalError,
                    "unrecognized runtime decision; failing closed",
                ),
                policy_version,
                policy_verification,
            }),
        }
    }

    /// Like [`run`](Self::run), but when the policy asks for approval this
    /// records the request in `config.ledger` and BLOCKS, polling the ledger
    /// until a human approves or denies it (via the `agent-guard` CLI) or the
    /// timeout elapses (S7-4).
    ///
    /// - approved → the action executes and `Executed` is returned;
    /// - denied   → `Denied { ApprovalDenied }`;
    /// - timeout  → the request is marked `expired` and `Denied { ApprovalDenied }`.
    ///
    /// Non-ask outcomes (execute / deny / handoff) pass straight through, so
    /// `run`'s behaviour is unchanged for everything except the ask path.
    /// Approval never overrides a current deny: the record binding and current
    /// policy are revalidated immediately before execution.
    pub fn run_until_approved(
        &self,
        input: &GuardInput,
        sandbox: &dyn Sandbox,
        config: &ApprovalConfig,
    ) -> RuntimeResult {
        match self.run(input, sandbox)? {
            RuntimeOutcome::AskForApproval {
                request_id,
                message,
                policy_version,
                policy_verification,
                ..
            } => self.wait_and_resume(
                input,
                sandbox,
                config,
                request_id,
                message,
                policy_version,
                policy_verification,
            ),
            passthrough => Ok(passthrough),
        }
    }

    /// Record a pending approval, block until a decision or timeout, then
    /// resume (on approve) or deny.
    #[allow(clippy::too_many_arguments)]
    fn wait_and_resume(
        &self,
        input: &GuardInput,
        sandbox: &dyn Sandbox,
        config: &ApprovalConfig,
        request_id: String,
        message: String,
        policy_version: String,
        policy_verification: PolicyVerification,
    ) -> RuntimeResult {
        // The wall-clock deadline is written into the ledger before the wait
        // begins, so a later `Expired` can be checked by anyone holding the
        // ledger. The monotonic `Instant` below is what the loop actually
        // waits on — it cannot jump if the system clock moves — but it is not
        // serialisable, so it is a companion to the recorded bound rather than
        // a substitute for it.
        config
            .ledger
            .create_pending(
                request_id.clone(),
                input.tool.name(),
                sha256_hash(&input.payload),
                message,
                input.context.agent_id.clone(),
                Some(config.timeout),
            )
            .map_err(|e| {
                SandboxError::ExecutionFailed(format!("approval ledger write failed: {e}"))
            })?;

        let deadline = Instant::now() + config.timeout;
        loop {
            let record = config.ledger.get(&request_id).map_err(|e| {
                SandboxError::ExecutionFailed(format!("approval ledger read failed: {e}"))
            })?;
            let status = record
                .as_ref()
                .map(|record| record.status)
                .unwrap_or(ApprovalStatus::Pending);

            match status {
                ApprovalStatus::Approved => {
                    // `record` is `Some` whenever a status was read (a `None`
                    // record yields `Pending` above, never `Approved`). If that
                    // invariant is ever violated, fail closed rather than
                    // fabricating an unauthenticated proof (`decided_by: None,
                    // decided_at: 0`) that would execute with no human attribution.
                    let Some(record) = record else {
                        return Err(SandboxError::ExecutionFailed(format!(
                            "approval ledger inconsistency: status Approved but no record for '{request_id}'"
                        )));
                    };
                    if let Err(message) = approval_record_matches(&record, input, &request_id) {
                        return Ok(RuntimeOutcome::Denied {
                            request_id,
                            reason: DecisionReason::new(DecisionCode::ApprovalDenied, message),
                            policy_version,
                            policy_verification,
                        });
                    }
                    let approval = approval_proof_from_record(record);
                    return self.resume_execution(input, sandbox, request_id, approval);
                }
                ApprovalStatus::Denied => {
                    return Ok(RuntimeOutcome::Denied {
                        request_id,
                        reason: DecisionReason::new(
                            DecisionCode::ApprovalDenied,
                            "approval request was denied",
                        ),
                        policy_version,
                        policy_verification,
                    })
                }
                ApprovalStatus::Expired | ApprovalStatus::Pending => {
                    if Instant::now() >= deadline {
                        // Terminal mark. `AlreadyDecided` is expected when the
                        // request was resolved concurrently; any other error is
                        // a real ledger write failure that would leave the
                        // ledger `Pending` while we return a denial, so surface
                        // it rather than discarding it silently.
                        if let Err(e) = config.ledger.decide(
                            &request_id,
                            ApprovalStatus::Expired,
                            Some("timeout".to_string()),
                        ) {
                            if !matches!(e, ApprovalError::AlreadyDecided { .. }) {
                                tracing::error!(
                                    request_id = %request_id,
                                    error = %e,
                                    "failed to mark approval request Expired in ledger; state/audit may be inconsistent"
                                );
                            }
                        }
                        return Ok(RuntimeOutcome::Denied {
                            request_id,
                            reason: DecisionReason::new(
                                DecisionCode::ApprovalDenied,
                                "approval request timed out",
                            ),
                            policy_version,
                            policy_verification,
                        });
                    }
                    std::thread::sleep(config.poll_interval);
                }
            }
        }
    }

    /// Execute an approved action after revalidating the exact input against
    /// the current policy snapshot. A repeated `ask` is expected and the
    /// approval upgrades only that exact action; a new deny or policy
    /// verification failure wins.
    fn resume_execution(
        &self,
        input: &GuardInput,
        sandbox: &dyn Sandbox,
        request_id: String,
        approval: ApprovalProof,
    ) -> RuntimeResult {
        let state = self.state.load();
        let policy_version = state.engine.version().to_string();
        if state.policy_verification.should_fail_closed() {
            return Ok(RuntimeOutcome::Denied {
                request_id,
                reason: DecisionReason::new(
                    DecisionCode::PolicyVerificationFailed,
                    "policy signature verification failed during approval revalidation",
                ),
                policy_version,
                policy_verification: state.policy_verification.clone(),
            });
        }

        let current_decision = self.evaluate_policy_only(input, &state);
        if let GuardDecision::Deny { reason } = current_decision {
            return Ok(RuntimeOutcome::Denied {
                request_id,
                reason,
                policy_version,
                policy_verification: state.policy_verification.clone(),
            });
        }
        if !matches!(
            current_decision,
            GuardDecision::Allow | GuardDecision::AskUser { .. }
        ) {
            return Ok(RuntimeOutcome::Denied {
                request_id,
                reason: DecisionReason::new(
                    DecisionCode::InternalError,
                    "unrecognized decision during approval revalidation; failing closed",
                ),
                policy_version,
                policy_verification: state.policy_verification.clone(),
            });
        }

        match self.execute_allowed(
            input,
            sandbox,
            &request_id,
            &state,
            policy_version,
            &GuardDecision::Allow,
            Some(approval),
        )? {
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
            // `execute_allowed` with `Allow` only yields `Executed`; map the
            // other variants defensively rather than panicking.
            ExecuteOutcome::Denied {
                decision,
                policy_version,
                policy_verification,
            } => {
                let reason = match decision {
                    GuardDecision::Deny { reason } => reason,
                    _ => DecisionReason::new(
                        DecisionCode::InternalError,
                        "execution denied after approval",
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
                policy_version,
                policy_verification,
                ..
            } => Ok(RuntimeOutcome::Denied {
                request_id,
                reason: DecisionReason::new(
                    DecisionCode::InternalError,
                    "unexpected ask after approval",
                ),
                policy_version,
                policy_verification,
            }),
        }
    }

    pub fn run_default(&self, input: &GuardInput) -> RuntimeResult {
        let sandbox = Self::default_sandbox();
        self.run(input, sandbox.as_ref())
    }
}

fn approval_record_matches(
    record: &ApprovalRecord,
    input: &GuardInput,
    request_id: &str,
) -> Result<(), String> {
    let decided_at = record
        .decided_at
        .ok_or_else(|| "approved record has no decision timestamp".to_string())?;
    if record
        .expires_at
        .is_some_and(|expires_at| decided_at >= expires_at)
    {
        return Err("approval was recorded after its expiry; refusing late approval".to_string());
    }
    if record.request_id != request_id
        || record.tool != input.tool.name()
        || record.payload_hash != sha256_hash(&input.payload)
        || record.agent_id.as_deref() != input.context.agent_id.as_deref()
        || decided_at < record.created_at
    {
        return Err(
            "approval record no longer matches the exact request; refusing execution".to_string(),
        );
    }
    Ok(())
}

/// Build the signed approval provenance (S7-5) from a decided ledger record.
fn approval_proof_from_record(record: ApprovalRecord) -> ApprovalProof {
    ApprovalProof {
        request_id: record.request_id,
        decided_by: record.decided_by,
        decided_at: record
            .decided_at
            .map(|ts| ts.timestamp().max(0) as u64)
            .unwrap_or(0),
    }
}
