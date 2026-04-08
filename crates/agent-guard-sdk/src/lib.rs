pub mod guard;
pub mod metrics;
pub mod anomaly;
pub mod provenance;
pub mod siem;

pub use anomaly::{get_detector, AnomalyDetector, AnomalyStatus};
pub use metrics::{get_metrics, Metrics};
pub use provenance::{ExecutionReceipt, RECEIPT_VERSION};
pub use siem::SiemExporter;
pub use prometheus_client;
pub use guard::{ExecuteOutcome, ExecuteResult, Guard, GuardInitError};

// Re-export core types so SDK users don't need to depend on agent-guard-core
pub use agent_guard_core::{
    AuditConfig, AuditDecision, AuditEvent, AuditRecord, Context, CustomToolId, DecisionCode, 
    DecisionReason, GuardDecision, GuardInput, ReloadEvent, ReloadStatus, Tool, TrustLevel,
    AnomalyEvent, ExecutionEvent, SandboxFailureEvent
};

// Re-export sandbox types for direct usage
pub use agent_guard_sandbox::{
    CapabilityDoctor, HealthStatus, Sandbox, SandboxCapabilities, SandboxContext, SandboxError,
    SandboxOutput, SandboxReport,
};
