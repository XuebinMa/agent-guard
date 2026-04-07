pub mod noop;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(feature = "macos-sandbox")]
pub mod macos;

#[cfg(feature = "windows-sandbox")]
pub mod windows;

pub use noop::NoopSandbox;
#[cfg(target_os = "linux")]
pub use linux::SeccompSandbox;
#[cfg(feature = "macos-sandbox")]
pub use macos::SeatbeltSandbox;
#[cfg(feature = "windows-sandbox")]
pub use windows::JobObjectSandbox;

use std::path::PathBuf;

use serde::Serialize;
use thiserror::Error;

use agent_guard_core::PolicyMode;

// ── SandboxContext ────────────────────────────────────────────────────────────

/// Runtime constraints for a sandboxed execution.
///
/// `timeout_ms` is an execution-time constraint, not a policy field.
/// Policy decides *whether* a command can run; context decides *how long* it may run.
/// This separation ensures policy YAML stays free of scheduling parameters.
#[derive(Debug, Clone)]
pub struct SandboxContext {
    /// Effective mode resolved by `PolicyEngine::effective_mode()`.
    /// The sandbox uses this to select its syscall allowlist.
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

/// Descriptive metadata about a sandbox's security features.
#[derive(Debug, Clone, Serialize)]
pub struct SandboxCapabilities {
    pub syscall_filtering: bool,
    pub filesystem_isolation: bool,
    pub network_blocking: bool,
    pub resource_limits: bool,
    pub process_tree_cleanup: bool,
}

// ── SandboxResult ─────────────────────────────────────────────────────────────

pub type SandboxResult = Result<SandboxOutput, SandboxError>;

// ── Sandbox trait ─────────────────────────────────────────────────────────────

/// Abstraction over execution environments.
///
/// Platform support matrix:
/// - Linux: seccomp-bpf syscall filter — **Phase 2** (`SeccompSandbox`)
/// - macOS: `sandbox-exec` profiles — **Phase 3 experimental**
/// - Windows: job object restrictions — **Phase 4**
///
/// Current default is `NoopSandbox` (passthrough): enforces policy but
/// provides no OS-level syscall or filesystem isolation.
pub trait Sandbox: Send + Sync {
    /// Friendly display name for the sandbox instance.
    fn name(&self) -> &'static str;

    /// Machine-readable identifier for the sandbox technology (e.g. "linux-seccomp").
    fn sandbox_type(&self) -> &'static str;

    /// Return detailed security capabilities for this sandbox.
    fn capabilities(&self) -> SandboxCapabilities;

    /// Execute `command` under this sandbox with the given context.
    ///
    /// Callers must run `Guard::check()` and receive `Allow` before calling
    /// this method. The sandbox provides defense-in-depth, not primary enforcement.
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
    /// Child process was killed by the seccomp filter (signal 31 / SIGSYS).
    ///
    /// This means the child attempted a syscall that was blocked by the installed
    /// BPF filter. The exit code is captured for diagnosis.
    #[error("process killed by seccomp filter (exit code: {exit_code})")]
    KilledByFilter { exit_code: i32 },
}
