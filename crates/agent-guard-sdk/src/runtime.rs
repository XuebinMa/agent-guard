use agent_guard_core::{DecisionReason, GuardDecision, RuntimeDecision};
use agent_guard_sandbox::{SandboxError, SandboxOutput};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{policy_signing::PolicyVerification, provenance::ExecutionReceipt};

pub type RuntimeResult = Result<RuntimeOutcome, SandboxError>;

/// Failure to close a host-handoff audit lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HandoffReportError {
    #[error(
        "no pending handoff for request ID '{request_id}' (it is unknown, expired, or already reported)"
    )]
    UnknownRequest { request_id: String },
    #[error("the pending handoff registry is unavailable")]
    RegistryUnavailable,
}

/// One policy evaluation and the metadata from the exact policy snapshot that
/// produced it.
///
/// This is the race-free decision surface for adapters: callers must not fetch
/// `policy_version()` or `policy_verification()` separately after a decision,
/// because a concurrent reload can move those accessors to a newer snapshot.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct DecisionEvaluation {
    pub request_id: String,
    pub decision: GuardDecision,
    pub runtime_decision: RuntimeDecision,
    pub policy_version: String,
    pub policy_verification: PolicyVerification,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RuntimeOutcome {
    Executed {
        request_id: String,
        output: SandboxOutput,
        policy_version: String,
        receipt: Option<ExecutionReceipt>,
        policy_verification: PolicyVerification,
    },
    Handoff {
        request_id: String,
        policy_version: String,
        policy_verification: PolicyVerification,
    },
    Denied {
        request_id: String,
        reason: DecisionReason,
        policy_version: String,
        policy_verification: PolicyVerification,
    },
    AskForApproval {
        request_id: String,
        message: String,
        reason: DecisionReason,
        policy_version: String,
        policy_verification: PolicyVerification,
    },
}

/// Result reported by the host after executing a `RuntimeOutcome::Handoff` action.
///
/// Hosts execute handoff actions outside the SDK sandbox, so the audit stream
/// otherwise goes blind after the handoff decision. `Guard::report_handoff_result`
/// consumes this and emits a matching `AuditRecord::ExecutionReported` through
/// the existing SIEM/audit pipeline, closing the audit loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffResult {
    pub exit_code: i32,
    pub duration_ms: u64,
    pub stderr: Option<String>,
    /// The host's signature over this outcome, if it can produce one.
    ///
    /// Optional because most hosts cannot: a host with no signing key has
    /// nothing honest to put here, and inventing a value would be worse than
    /// leaving the claim visibly unbacked. The Guard attaches this to the
    /// audit record only when it describes the outcome actually reported.
    #[serde(default)]
    pub attestation: Option<agent_guard_core::HostAttestation>,
}
