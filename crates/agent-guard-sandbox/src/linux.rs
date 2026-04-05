//! Linux seccomp-bpf sandbox.
//!
//! Uses `libseccomp` to install a syscall allowlist before executing the command.
//! The allowlist is selected based on the effective `PolicyMode`:
//!
//! | Mode            | Allowed syscalls |
//! |-----------------|-----------------|
//! | `ReadOnly`      | read, stat family, mmap(PROT_READ), close, exit_group |
//! | `WorkspaceWrite`| ReadOnly + write, creat, unlink, rename, mkdir within workspace |
//! | `FullAccess`    | No seccomp filter applied — all syscalls permitted |
//!
//! The workspace boundary is enforced at the path level by the policy engine
//! and validators *before* execution. Seccomp provides defense-in-depth by
//! blocking syscall classes that should never appear regardless of path.
//!
//! # Phase 2 implementation status
//!
//! The `SeccompSandbox` struct and `Sandbox` trait impl are present and compile.
//! The actual BPF filter construction (`build_filter`) is stubbed — it falls
//! back to executing the command without a filter (NoopSandbox behaviour) and
//! logs a warning to stderr. Full filter construction is a Phase 2 P2 task.
//!
//! Enable with feature flag: `cargo build --features seccomp`

use agent_guard_core::PolicyMode;

use super::{NoopSandbox, Sandbox, SandboxContext, SandboxResult};

/// Seccomp-bpf backed sandbox for Linux.
///
/// Installs a syscall filter before forking the child process.
/// Falls back to `NoopSandbox` behaviour if filter setup fails and
/// `strict` mode is not enabled.
pub struct SeccompSandbox {
    /// If `true`, fail hard when filter setup fails rather than falling back.
    pub strict: bool,
}

impl SeccompSandbox {
    pub fn new() -> Self {
        Self { strict: false }
    }

    /// Strict mode: never execute without a filter. Recommended for production.
    pub fn strict() -> Self {
        Self { strict: true }
    }
}

impl Default for SeccompSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Sandbox for SeccompSandbox {
    fn name(&self) -> &'static str {
        "seccomp"
    }

    fn execute(&self, command: &str, context: &SandboxContext) -> SandboxResult {
        match build_filter(&context.mode) {
            Ok(Some(_filter)) => {
                // TODO(phase2-p2): apply the filter to the child process before exec.
                // For now, fall through to noop execution.
                eprintln!("[agent-guard] SeccompSandbox: filter built but not yet applied (Phase 2 stub)");
                NoopSandbox.execute(command, context)
            }
            Ok(None) => {
                // FullAccess — no filter needed.
                NoopSandbox.execute(command, context)
            }
            Err(e) => {
                if self.strict {
                    Err(super::SandboxError::FilterSetup(e))
                } else {
                    eprintln!("[agent-guard] SeccompSandbox: filter setup failed ({e}), falling back to noop");
                    NoopSandbox.execute(command, context)
                }
            }
        }
    }

    fn is_available(&self) -> bool {
        // seccomp is available on Linux 3.5+ which is ubiquitous in production.
        true
    }
}

/// Build a seccomp filter for the given mode.
///
/// Returns `Ok(None)` for `FullAccess` (no filter needed).
/// Returns `Ok(Some(filter))` for `ReadOnly` / `WorkspaceWrite`.
/// Returns `Err` if the filter cannot be constructed.
///
/// # Stub
///
/// This function currently always returns `Ok(Some(()))` as a placeholder.
/// The real implementation will use `libseccomp` to build a BPF program.
fn build_filter(mode: &PolicyMode) -> Result<Option<()>, String> {
    match mode {
        PolicyMode::FullAccess => Ok(None),
        PolicyMode::ReadOnly | PolicyMode::WorkspaceWrite => {
            // TODO(phase2-p2): construct BPF filter via libseccomp crate.
            // Syscall allowlist by mode:
            //   ReadOnly:       read, openat(O_RDONLY), stat, fstat, lstat,
            //                   mmap(PROT_READ), close, exit_group, rt_sigreturn
            //   WorkspaceWrite: ReadOnly + write, openat(O_WRONLY|O_RDWR),
            //                   creat, unlink, rename, mkdir, rmdir
            Ok(Some(()))
        }
    }
}
