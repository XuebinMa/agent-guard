use agent_guard_core::RuntimeDecision;
use agent_guard_sandbox::{SandboxError, SandboxOutput};
use serde::Serialize;

use crate::{policy_signing::PolicyVerification, provenance::ExecutionReceipt};

pub type RuntimeResult = Result<RuntimeOutcome, SandboxError>;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RuntimeOutcome {
    Executed {
        output: SandboxOutput,
        policy_version: String,
        receipt: Option<ExecutionReceipt>,
        policy_verification: PolicyVerification,
    },
    Handoff {
        decision: RuntimeDecision,
        policy_version: String,
        policy_verification: PolicyVerification,
    },
    Denied {
        decision: RuntimeDecision,
        policy_version: String,
        policy_verification: PolicyVerification,
    },
    AskForApproval {
        decision: RuntimeDecision,
        policy_version: String,
        policy_verification: PolicyVerification,
    },
}
