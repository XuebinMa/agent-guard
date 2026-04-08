pub mod noop;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(feature = "macos-sandbox")]
pub mod macos;

#[cfg(feature = "windows-sandbox")]
pub mod windows;

#[cfg(feature = "windows-appcontainer")]
pub mod windows_appcontainer;

pub use noop::NoopSandbox;
#[cfg(target_os = "linux")]
pub use linux::SeccompSandbox;
#[cfg(feature = "macos-sandbox")]
pub use macos::SeatbeltSandbox;
#[cfg(feature = "windows-sandbox")]
pub use windows::JobObjectSandbox;
#[cfg(feature = "windows-appcontainer")]
pub use windows_appcontainer::AppContainerSandbox;

use std::path::PathBuf;

use serde::Serialize;
use thiserror::Error;

use agent_guard_core::PolicyMode;

// ── SandboxContext ────────────────────────────────────────────────────────────

/// Runtime constraints for a sandboxed execution.
#[derive(Debug, Clone)]
pub struct SandboxContext {
    /// Effective mode resolved by `PolicyEngine::effective_mode()`.
    pub mode: PolicyMode,
    /// Workspace root — writes must stay within this directory.
    pub working_directory: PathBuf,
    /// Optional execution timeout in milliseconds. `None` means no limit.
    pub timeout_ms: Option<u64>,
}

// ── SandboxOutput ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct SandboxOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

// ── SandboxCapabilities ────────────────────────────────────────────────────────

/// Descriptive metadata about a sandbox's security features based on the Unified Capability Model (UCM).
#[derive(Debug, Clone, Serialize)]
pub struct SandboxCapabilities {
    pub filesystem_read_workspace: bool,
    pub filesystem_read_global: bool,
    pub filesystem_write_workspace: bool,
    pub filesystem_write_global: bool,
    pub network_outbound_any: bool,
    pub network_outbound_internet: bool,
    pub network_outbound_local: bool,
    pub child_process_spawn: bool,
    pub registry_write: bool,
}

// ── SandboxResult ─────────────────────────────────────────────────────────────

pub type SandboxResult = Result<SandboxOutput, SandboxError>;

// ── Sandbox trait ─────────────────────────────────────────────────────────────

/// Abstraction over execution environments.
pub trait Sandbox: Send + Sync {
    /// Friendly display name for the sandbox instance (e.g. "Seatbelt").
    fn name(&self) -> &'static str;

    /// Machine-readable identifier for the sandbox technology (e.g. "macos-seatbelt").
    fn sandbox_type(&self) -> &'static str;

    /// Return detailed security capabilities for this sandbox.
    fn capabilities(&self) -> SandboxCapabilities;

    /// Execute `command` under this sandbox with the given context.
    fn execute(&self, command: &str, context: &SandboxContext) -> SandboxResult;

    /// Returns `true` if this sandbox implementation is usable on the current platform.
    fn is_available(&self) -> bool;
}

// ── SandboxError ──────────────────────────────────────────────────────────────

#[derive(Debug, Error, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum SandboxError {
    #[error("sandbox not available on this platform: {0}")]
    NotAvailable(String),
    #[error("execution failed: {0}")]
    ExecutionFailed(String),
    #[error("timeout after {ms}ms")]
    Timeout { ms: u64 },
    #[error("seccomp filter setup failed: {0}")]
    FilterSetup(String),
    #[error("process killed by seccomp filter (exit code: {exit_code})")]
    KilledByFilter { exit_code: i32 },
}

#[derive(Debug, Clone, Serialize)]
pub struct SandboxReport {
    pub name: &'static str,
    pub sandbox_type: &'static str,
    pub is_available: bool,
    pub capabilities: SandboxCapabilities,
    pub health: HealthStatus,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HealthStatus {
    Pass,
    Fail { error: String },
    Skipped,
}

/// Utility for detecting and reporting on the security posture of the current host.
pub struct CapabilityDoctor;

impl CapabilityDoctor {
    /// Returns a list of all sandboxes and their status on the current system.
    pub fn report() -> Vec<SandboxReport> {
        let sandboxes: Vec<Box<dyn Sandbox>> = vec![
            Box::new(NoopSandbox),
            #[cfg(target_os = "linux")]
            Box::new(linux::SeccompSandbox),
            #[cfg(feature = "macos-sandbox")]
            Box::new(macos::SeatbeltSandbox),
            #[cfg(feature = "windows-sandbox")]
            Box::new(JobObjectSandbox),
            #[cfg(feature = "windows-appcontainer")]
            Box::new(AppContainerSandbox),
        ];

        let mut reports = Vec::new();
        for sb in sandboxes {
            let available = sb.is_available();
            let health = if available {
                let ctx = SandboxContext {
                    mode: PolicyMode::ReadOnly,
                    working_directory: std::env::current_dir().unwrap_or_else(|_| ".".into()),
                    timeout_ms: Some(2000),
                };
                match sb.execute("echo 1", &ctx) {
                    Ok(_) => HealthStatus::Pass,
                    Err(e) => HealthStatus::Fail { error: e.to_string() },
                }
            } else {
                HealthStatus::Skipped
            };

            reports.push(SandboxReport {
                name: sb.name(),
                sandbox_type: sb.sandbox_type(),
                is_available: available,
                capabilities: sb.capabilities(),
                health,
            });
        }

        reports
    }
}
