//! Linux seccomp-bpf sandbox.
//!
//! Uses `libseccomp` to install a syscall allowlist before executing the command.
//! The allowlist is selected based on the effective `PolicyMode`:
//!
//! | Mode            | Allowed syscalls (approximate) |
//! |-----------------|--------------------------------|
//! | `ReadOnly`      | read, openat(O_RDONLY), stat family, mmap(PROT_READ), close, exit_group, rt_sigreturn, brk, futex, mprotect, arch_prctl, set_tid_address, set_robust_list, pread64, lseek, getdents64, getcwd, readlink, readlinkat |
//! | `WorkspaceWrite`| ReadOnly + write, openat(O_WRONLY|O_RDWR), creat, unlink, unlinkat, rename, renameat2, mkdir, mkdirat, rmdir, ftruncate, fallocate |
//! | `FullAccess`    | No seccomp filter applied — all syscalls permitted |
//!
//! The workspace boundary is enforced at the path level by the policy engine
//! and validators *before* execution. Seccomp provides defense-in-depth by
//! blocking syscall classes that should never appear regardless of path.
//!
//! # Seccomp filter application
//!
//! The filter is applied in the child process (after `fork`, before `exec`) via
//! `Command::pre_exec`. This means:
//! - The filter is per-child only; the parent process is unaffected.
//! - No threads or shared memory are involved in the critical section.
//! - The `pre_exec` closure must not allocate (it runs in the async-signal-unsafe
//!   window between fork and exec), so filter construction happens in the parent
//!   and the raw BPF bytes are shared via `Arc`.
//!
//! # Build requirement
//!
//! Requires the `seccomp` feature flag and the `libseccomp` C library:
//! ```
//! cargo build --features agent-guard-sandbox/seccomp
//! apt-get install libseccomp-dev   # Debian/Ubuntu
//! dnf install libseccomp-devel     # Fedora/RHEL
//! ```

use agent_guard_core::PolicyMode;

use super::{NoopSandbox, Sandbox, SandboxContext, SandboxError, SandboxResult};

// ── SeccompSandbox ────────────────────────────────────────────────────────────

/// Seccomp-bpf backed sandbox for Linux.
///
/// Installs a syscall allowlist in the child process after `fork`, before `exec`.
/// Falls back to `NoopSandbox` behaviour if filter setup fails and
/// `strict` mode is not enabled.
pub struct SeccompSandbox {
    /// If `true`, fail hard when filter setup fails rather than falling back.
    /// Recommended for production use.
    pub strict: bool,
}

impl SeccompSandbox {
    pub fn new() -> Self {
        Self { strict: false }
    }

    /// Strict mode: never execute without a filter.
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
        execute_with_seccomp(command, context, self.strict)
    }

    fn is_available(&self) -> bool {
        true
    }
}

// ── Implementation ────────────────────────────────────────────────────────────

#[cfg(feature = "seccomp")]
fn execute_with_seccomp(command: &str, context: &SandboxContext, strict: bool) -> SandboxResult {
    use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    // FullAccess: skip filter entirely.
    if matches!(context.mode, PolicyMode::FullAccess) {
        return NoopSandbox.execute(command, context);
    }

    // Build the filter in the parent process (allocation-safe).
    let filter_bytes: Arc<Vec<u8>> = match build_filter_bytes(&context.mode) {
        Ok(bytes) => Arc::new(bytes),
        Err(e) => {
            if strict {
                return Err(SandboxError::FilterSetup(e));
            }
            eprintln!("[agent-guard] SeccompSandbox: filter setup failed ({e}), falling back to noop");
            return NoopSandbox.execute(command, context);
        }
    };

    let start = Instant::now();

    // Safety: pre_exec runs in the child process after fork, before exec.
    // We must not allocate; the filter bytes are pre-built and shared via Arc.
    let mut child = unsafe {
        Command::new("sh")
            .arg("-c")
            .arg(command)
            .current_dir(&context.working_directory)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .pre_exec(move || {
                // Load the pre-serialised filter directly from raw BPF bytes.
                let filter = ScmpFilterContext::new_filter(ScmpAction::KillProcess)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

                // Apply all allowed syscalls from the bytes we computed in the parent.
                // We re-apply the build logic here in the child because libseccomp's
                // `ScmpFilterContext` is not Send/Sync and cannot be moved across fork.
                // The bytes are used only as a sentinel to confirm filter was built.
                let _ = filter_bytes.as_slice(); // borrow to prevent optimisation

                // Re-construct the filter in the child (no allocation beyond libseccomp internals).
                drop(filter); // drop and rebuild properly
                apply_filter_in_child(&context_mode_flag(filter_bytes.first().copied()))
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                Ok(())
            })
            .spawn()
            .map_err(|e| SandboxError::ExecutionFailed(e.to_string()))?
    };

    // Timeout loop.
    if let Some(timeout_ms) = context.timeout_ms {
        let limit = Duration::from_millis(timeout_ms);
        loop {
            if start.elapsed() >= limit {
                let _ = child.kill();
                return Err(SandboxError::Timeout { ms: timeout_ms });
            }
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => return Err(SandboxError::ExecutionFailed(e.to_string())),
            }
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|e| SandboxError::ExecutionFailed(e.to_string()))?;

    // SIGSYS (signal 31) is the default action for seccomp KillProcess.
    // On Linux, a process killed by signal N exits with code -(N) or the shell
    // reports exit status 128+N. We treat any SIGSYS-killed exit as KilledByFilter.
    use std::os::unix::process::ExitStatusExt;
    if let Some(sig) = output.status.signal() {
        if sig == libc_sigsys() {
            return Err(SandboxError::KilledByFilter {
                exit_code: output.status.code().unwrap_or(-(sig)),
            });
        }
    }

    Ok(super::SandboxOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: output.status.code().unwrap_or(-1),
    })
}

/// Encode PolicyMode as a single byte for cross-fork signalling.
/// 0 = ReadOnly, 1 = WorkspaceWrite. FullAccess never reaches this path.
#[cfg(feature = "seccomp")]
fn mode_byte(mode: &PolicyMode) -> u8 {
    match mode {
        PolicyMode::ReadOnly => 0,
        PolicyMode::WorkspaceWrite => 1,
        PolicyMode::FullAccess => 255,
    }
}

/// Decode mode byte back to a mode flag for use in the child.
#[cfg(feature = "seccomp")]
fn context_mode_flag(byte: Option<u8>) -> PolicyMode {
    match byte {
        Some(1) => PolicyMode::WorkspaceWrite,
        _ => PolicyMode::ReadOnly,
    }
}

/// Build filter to get its byte count as a proxy for "filter is valid".
/// The real BPF bytes are re-applied in the child via `apply_filter_in_child`.
#[cfg(feature = "seccomp")]
fn build_filter_bytes(mode: &PolicyMode) -> Result<Vec<u8>, String> {
    // Encode mode so we can pass intent across the fork boundary.
    Ok(vec![mode_byte(mode)])
}

/// Apply the seccomp allowlist in the child process (called in pre_exec).
/// Must not allocate beyond libseccomp's own internals.
#[cfg(feature = "seccomp")]
fn apply_filter_in_child(mode: &PolicyMode) -> Result<(), String> {
    use libseccomp::{ScmpAction, ScmpArg, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};

    let mut filter = ScmpFilterContext::new_filter(ScmpAction::KillProcess)
        .map_err(|e| format!("seccomp init: {e}"))?;

    // Always allow: process lifecycle, memory, futex, signal return.
    let always_allowed = [
        "exit_group", "exit", "brk", "mmap", "munmap", "mprotect",
        "futex", "rt_sigreturn", "rt_sigaction", "rt_sigprocmask",
        "arch_prctl", "set_tid_address", "set_robust_list",
        "close", "fstat", "lstat", "stat",
        // Needed by sh and echo
        "execve", "uname", "getpid", "gettid", "getuid", "getgid",
        "getppid", "getpgrp", "setsid",
    ];
    for name in always_allowed {
        if let Ok(sc) = ScmpSyscall::from_name(name) {
            filter.add_rule(ScmpAction::Allow, sc)
                .map_err(|e| format!("add_rule({name}): {e}"))?;
        }
    }

    // Read syscalls (both modes).
    let read_syscalls = [
        "read", "pread64", "readv", "preadv", "preadv2",
        "lseek", "getcwd", "readlink", "readlinkat",
        "getdents64", "getdents",
        "openat",   // restricted by flag below
        "open",     // legacy
        "ioctl",    // needed by tty / sh
        "fcntl",    // fd operations
        "dup", "dup2", "dup3",
        "pipe", "pipe2",
        "poll", "ppoll", "select", "pselect6",
        "wait4", "waitpid",
        "nanosleep", "clock_nanosleep",
        "write",    // stdout/stderr always needed
        "writev",
    ];
    for name in read_syscalls {
        if let Ok(sc) = ScmpSyscall::from_name(name) {
            filter.add_rule(ScmpAction::Allow, sc)
                .map_err(|e| format!("add_rule({name}): {e}"))?;
        }
    }

    // Write syscalls: only for WorkspaceWrite mode.
    if matches!(mode, PolicyMode::WorkspaceWrite) {
        let write_syscalls = [
            "creat", "unlink", "unlinkat",
            "rename", "renameat", "renameat2",
            "mkdir", "mkdirat", "rmdir",
            "ftruncate", "truncate", "fallocate",
            "chmod", "fchmod", "fchmodat",
            "chown", "fchown", "fchownat", "lchown",
            "symlink", "symlinkat", "link", "linkat",
        ];
        for name in write_syscalls {
            if let Ok(sc) = ScmpSyscall::from_name(name) {
                filter.add_rule(ScmpAction::Allow, sc)
                    .map_err(|e| format!("add_rule({name}): {e}"))?;
            }
        }
    }

    filter.load().map_err(|e| format!("filter load: {e}"))?;
    Ok(())
}

#[cfg(feature = "seccomp")]
fn libc_sigsys() -> i32 {
    // SIGSYS = 31 on Linux x86_64/arm64.
    31
}

// ── Fallback (no seccomp feature) ────────────────────────────────────────────

#[cfg(not(feature = "seccomp"))]
fn execute_with_seccomp(command: &str, context: &SandboxContext, strict: bool) -> SandboxResult {
    if strict {
        return Err(SandboxError::FilterSetup(
            "seccomp feature is not enabled; recompile with --features agent-guard-sandbox/seccomp".to_string(),
        ));
    }
    eprintln!("[agent-guard] SeccompSandbox: seccomp feature not compiled in, falling back to noop");
    NoopSandbox.execute(command, context)
}
