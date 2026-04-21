use agent_guard_core::DecisionReason;
use agent_guard_sandbox::{SandboxError, SandboxOutput};
use serde::{Deserialize, Serialize};

use crate::{policy_signing::PolicyVerification, provenance::ExecutionReceipt};

pub type RuntimeResult = Result<RuntimeOutcome, SandboxError>;

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
/// consumes this and emits a matching `AuditRecord::ExecutionFinished` through
/// the existing SIEM/audit pipeline, closing the audit loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffResult {
    pub exit_code: i32,
    pub duration_ms: u64,
    pub stderr: Option<String>,
}
