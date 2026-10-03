//! One-shot state retained while execution is handed to a host.
//!
//! A handoff can straddle a policy reload. Keeping the original state snapshot
//! here ensures its terminal record reaches the same audit sinks and preserves
//! the original tool/agent identity. The registry is bounded and entries
//! expire so a host that never reports a result cannot grow memory forever.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agent_guard_core::{AuditRecord, ExecutionEvent, GuardInput};
use agent_guard_sandbox::SandboxError;

use crate::guard::{Guard, GuardState};
use crate::runtime::{HandoffReportError, HandoffResult};

const MAX_PENDING_HANDOFFS: usize = 4_096;
const PENDING_HANDOFF_TTL: Duration = Duration::from_secs(60 * 60);

pub(crate) struct PendingHandoff {
    state: Arc<GuardState>,
    agent_id: Option<String>,
    tool: String,
    audit_enabled: bool,
    created_at: Instant,
}

#[derive(Default)]
pub(crate) struct PendingHandoffs {
    entries: Mutex<HashMap<String, PendingHandoff>>,
}

impl PendingHandoffs {
    fn register(
        &self,
        request_id: &str,
        state: Arc<GuardState>,
        input: &GuardInput,
    ) -> Result<(), SandboxError> {
        let mut entries = self.entries.lock().map_err(|_| {
            SandboxError::ExecutionFailed("pending handoff registry is unavailable".to_string())
        })?;
        entries.retain(|_, entry| entry.created_at.elapsed() <= PENDING_HANDOFF_TTL);

        if entries.contains_key(request_id) {
            return Err(SandboxError::ExecutionFailed(
                "duplicate handoff request ID; refusing execution".to_string(),
            ));
        }

        if entries.len() >= MAX_PENDING_HANDOFFS {
            // A disabled audit sink emits no lifecycle evidence, but the
            // request ID must still remain a one-shot capability so language
            // bindings can reject forged and duplicate reports. Keep that
            // registry bounded without ever evicting a pending audited
            // lifecycle: only the oldest audit-disabled entry is expendable.
            let evictable = entries
                .iter()
                .filter(|(_, entry)| !entry.audit_enabled)
                .min_by_key(|(_, entry)| entry.created_at)
                .map(|(request_id, _)| request_id.clone());
            if let Some(evictable) = evictable {
                entries.remove(&evictable);
            } else {
                return Err(SandboxError::ExecutionFailed(format!(
                    "pending handoff limit ({MAX_PENDING_HANDOFFS}) reached; refusing an unreportable handoff"
                )));
            }
        }

        let audit_enabled = state.audit_cfg.enabled;
        entries.insert(
            request_id.to_string(),
            PendingHandoff {
                state,
                agent_id: input.context.agent_id.clone(),
                tool: input.tool.name().to_string(),
                audit_enabled,
                created_at: Instant::now(),
            },
        );
        Ok(())
    }

    fn take(&self, request_id: &str) -> Result<PendingHandoff, HandoffReportError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| HandoffReportError::RegistryUnavailable)?;
        let entry =
            entries
                .remove(request_id)
                .ok_or_else(|| HandoffReportError::UnknownRequest {
                    request_id: request_id.to_string(),
                })?;
        if entry.created_at.elapsed() > PENDING_HANDOFF_TTL {
            return Err(HandoffReportError::UnknownRequest {
                request_id: request_id.to_string(),
            });
        }
        Ok(entry)
    }
}

impl Guard {
    pub(crate) fn register_handoff(
        &self,
        request_id: &str,
        state: Arc<GuardState>,
        input: &GuardInput,
    ) -> Result<(), SandboxError> {
        self.pending_handoffs.register(request_id, state, input)
    }

    /// Report one host-executed handoff outcome.
    ///
    /// The request ID is a one-shot capability returned by [`Guard::run`].
    /// Unknown, expired, or already-reported IDs are rejected, and the
    /// terminal event uses the exact state snapshot, audit destinations,
    /// tool, and agent captured before the handoff left the Guard boundary.
    pub fn try_report_handoff_result(
        &self,
        request_id: &str,
        result: HandoffResult,
    ) -> Result<(), HandoffReportError> {
        let pending = self.pending_handoffs.take(request_id)?;
        let stderr_present = result.stderr.is_some();
        // An attestation is only evidence for the claim it actually signs.
        // A host that signs one outcome and reports another has attested to
        // nothing about this record, so the signature is dropped rather than
        // recorded next to a result it does not cover.
        let attestation = result.attestation.filter(|attestation| {
            let describes_report =
                attestation.describes(request_id, result.exit_code, result.duration_ms);
            if !describes_report {
                tracing::warn!(
                    request_id = request_id,
                    key_id = %attestation.key_id,
                    "host attestation describes a different outcome than the one reported; \
                     recording the outcome as unattested"
                );
            }
            describes_report
        });

        let event = ExecutionEvent {
            timestamp: chrono::Utc::now(),
            request_id: request_id.to_string(),
            agent_id: pending.agent_id,
            tool: pending.tool,
            sandbox_type: "host-handoff".to_string(),
            duration_ms: Some(result.duration_ms),
            exit_code: Some(result.exit_code),
            host_attestation: attestation,
        };
        self.emit_record(&pending.state, AuditRecord::ExecutionReported(event));

        if stderr_present {
            tracing::debug!(
                request_id = request_id,
                "handoff result carried stderr; not included in core ExecutionEvent schema"
            );
        }
        Ok(())
    }

    /// Compatibility wrapper around [`Guard::try_report_handoff_result`].
    /// New integrations should use the fallible form so stale or duplicate
    /// report attempts are visible to the host.
    pub fn report_handoff_result(&self, request_id: &str, result: HandoffResult) {
        if let Err(error) = self.try_report_handoff_result(request_id, result) {
            tracing::warn!(request_id = request_id, %error, "handoff result was not recorded");
        }
    }
}
