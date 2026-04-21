pub mod anomaly;
pub mod doctor;
pub mod guard;
pub mod metrics;
pub mod policy_signing;
pub mod provenance;
pub mod runtime;
pub mod siem;

pub use anomaly::{get_detector, AnomalyDetector, AnomalyStatus};
pub use doctor::{collect_doctor_report, render_doctor_html, render_doctor_text, DoctorReport};
pub use guard::{DefaultSandboxDiagnosis, ExecuteOutcome, ExecuteResult, Guard, GuardInitError};
pub use metrics::{get_metrics, Metrics};
pub use policy_signing::{
    load_policy_signature_file, load_public_key_file, parse_hex_signing_key, sign_policy,
    verify_policy, PolicyVerification, PolicyVerificationStatus,
};
pub use prometheus_client;
pub use provenance::{ExecutionReceipt, RECEIPT_VERSION};
pub use runtime::{HandoffResult, RuntimeOutcome, RuntimeResult};
pub use siem::SiemExporter;

// Re-export core types so SDK users don't need to depend on agent-guard-core
pub use agent_guard_core::{
    AnomalyEvent, AuditConfig, AuditDecision, AuditEvent, AuditRecord, Context, CustomToolId,
    DecisionCode, DecisionReason, ExecutionEvent, GuardDecision, GuardInput, ReloadEvent,
    ReloadStatus, RuntimeDecision, SandboxFailureEvent, Tool, TrustLevel,
};

// Re-export sandbox types for direct usage
pub use agent_guard_sandbox::{
    CapabilityDoctor, HealthStatus, RuntimeCheck, RuntimeCheckStatus, Sandbox, SandboxCapabilities,
    SandboxContext, SandboxError, SandboxOutput, SandboxReport,
};
