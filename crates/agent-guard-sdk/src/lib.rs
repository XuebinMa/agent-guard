pub mod anomaly;
pub mod guard;
pub mod metrics;
pub mod provenance;
pub mod siem;

pub use anomaly::{get_detector, AnomalyDetector, AnomalyStatus};
pub use guard::{DefaultSandboxDiagnosis, ExecuteOutcome, ExecuteResult, Guard, GuardInitError};
pub use metrics::{get_metrics, Metrics};
pub use prometheus_client;
pub use provenance::{ExecutionReceipt, RECEIPT_VERSION};
pub use siem::SiemExporter;

// Re-export core types so SDK users don't need to depend on agent-guard-core
pub use agent_guard_core::{
    AnomalyEvent, AuditConfig, AuditDecision, AuditEvent, AuditRecord, Context, CustomToolId,
    DecisionCode, DecisionReason, ExecutionEvent, GuardDecision, GuardInput, ReloadEvent,
    ReloadStatus, SandboxFailureEvent, Tool, TrustLevel,
};

// Re-export sandbox types for direct usage
pub use agent_guard_sandbox::{
    CapabilityDoctor, HealthStatus, RuntimeCheck, RuntimeCheckStatus, Sandbox, SandboxCapabilities,
    SandboxContext, SandboxError, SandboxOutput, SandboxReport,
};
