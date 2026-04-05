//! Linux seccomp-bpf sandbox.
//!
//! Uses `libseccomp` to install a syscall allowlist before executing the command.
//! The allowlist is selected based on the effective `PolicyMode`:
//!
//! | Mode             | Allowed syscalls                                                                |
//! |------------------|---------------------------------------------------------------------------------|
//! | `ReadOnly`       | read/pread64/readv family, openat/open **O_RDONLY only** (arg-filtered),        |
//! |                  | stat/fstat/lstat, lseek, getdents64, getcwd, readlink, close, mmap/mprotect,   |
//! |                  | write/writev **fd ≤ 2 only** (stdout/stderr), dup/pipe, poll/select,            |
//! |                  | wait4, futex, brk, rt_sig*, exit_group, execve, process identity syscalls      |
//! | `WorkspaceWrite` | ReadOnly + unrestricted write/writev, openat/open with any flags,               |
//! |                  | creat, unlink/unlinkat, rename family, mkdir/mkdirat/rmdir, ftruncate/truncate, |
//! |                  | fallocate, chmod/chown family, symlink/link family                              |
//! | `FullAccess`     | No seccomp filter applied — all syscalls permitted                              |
//!
//! # Design notes
//!
//! ## Argument filtering for `ReadOnly`
//!
//! Simply allowlisting `openat` without restricting its `flags` argument
//! would let the child open files with `O_WRONLY | O_RDWR | O_TRUNC`, defeating
//! the read-only guarantee. We use `ScmpArgCompare` with `ScmpCompareOp::MaskedEqual`
//! to restrict the flags argument: `(flags & O_ACCMODE) == O_RDONLY`.
//!
//!   - `open(path, flags)`:   flags is argument index 1
//!   - `openat(dfd, path, flags)`: flags is argument index 2
//!
//! `O_ACCMODE = 0x3` masks the access-mode bits. `O_RDONLY = 0x0` means read-only.
//! This allows `O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_DIRECTORY | …` but blocks
//! `O_WRONLY (1)`, `O_RDWR (2)`, and therefore `O_TRUNC` (meaningless without write).
//!
//! Similarly, `write` / `writev` are needed for stdout/stderr even in read-only
//! mode. We restrict them to fd ≤ 2 via `ScmpCompareOp::LessOrEqual`.
//!
//! ## KilledByFilter detection
//!
//! When seccomp's `KillProcess` action fires, the kernel sends SIGSYS to the
//! child. Two observable outcomes in the parent:
//!   1. `ExitStatus::signal() == SIGSYS` — child received signal directly
//!   2. `ExitStatus::code() == 128 + SIGSYS` — shell converted signal to exit code
//!
//! Both are checked; `libc::SIGSYS` is used instead of a hard-coded constant.
//!
//! ## Noop fallback is unsafe for production
//!
//! When `strict = false` (the default) and filter setup fails, the sandbox falls
//! back to `NoopSandbox`. **This means no OS-level isolation is applied.**
//! For production deployments, always use `SeccompSandbox::strict()`.
//!
//! ## pre_exec allocation constraint
//!
//! `Command::pre_exec` runs in the child after `fork`, before `exec`. The allocator
//! may be in a corrupt state (parent had a lock held at fork). We therefore encode
//! the mode as a single byte in an `Arc<[u8; 1]>` and call `apply_filter_in_child`
//! which uses only libseccomp's own heap.
//!
//! # Build requirement
//!
//! Requires the `seccomp` feature flag and the `libseccomp` C library:
//! ```text
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
///
/// # Strict mode
///
/// By default (`strict = false`), filter setup failure falls back to `NoopSandbox`
/// with a stderr warning. **This provides no isolation.** Use `SeccompSandbox::strict()`
/// in production to return `Err(FilterSetup)` instead of silently bypassing.
pub struct SeccompSandbox {
    /// If `true`, filter setup failure returns `Err(FilterSetup)` rather than
    /// falling back to `NoopSandbox`. Recommended for production use.
    pub strict: bool,
}

impl SeccompSandbox {
    /// Create a non-strict sandbox (falls back to noop on filter failure).
    ///
    /// **Warning:** suitable for development only. Use `strict()` in production.
    pub fn new() -> Self {
        Self { strict: false }
    }

    /// Create a strict sandbox: filter failure is always a hard error.
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

// ── Implementation (seccomp feature enabled) ──────────────────────────────────

#[cfg(feature = "seccomp")]
fn execute_with_seccomp(command: &str, context: &SandboxContext, strict: bool) -> SandboxResult {
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    // FullAccess: skip filter entirely.
    if matches!(context.mode, PolicyMode::FullAccess) {
        return NoopSandbox.execute(command, context);
    }

    // Probe filter construction in the parent to surface errors before forking.
    if let Err(e) = probe_filter(&context.mode) {
        if strict {
            return Err(SandboxError::FilterSetup(e));
        }
        eprintln!(
            "[agent-guard] SeccompSandbox: filter probe failed ({e}), \
             falling back to noop — NO OS-LEVEL ISOLATION IN EFFECT"
        );
        return NoopSandbox.execute(command, context);
    }

    // Encode mode as a single byte. This is the only data we pass across the
    // fork boundary without allocating in pre_exec.
    let mode_flag: Arc<[u8; 1]> = Arc::new([mode_byte(&context.mode)]);

    let start = Instant::now();

    // Safety: pre_exec runs in the child process after fork, before exec.
    // We only read `mode_flag[0]` (no allocation) and call into libseccomp.
    let mut child = unsafe {
        Command::new("sh")
            .arg("-c")
            .arg(command)
            .current_dir(&context.working_directory)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .pre_exec(move || {
                let mode = decode_mode_byte(mode_flag[0]);
                apply_filter_in_child(&mode)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                Ok(())
            })
            .spawn()
            .map_err(|e| SandboxError::ExecutionFailed(e.to_string()))?
    };

    // Timeout loop: poll every 10 ms until the process exits or the deadline passes.
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

    classify_exit_status(&output)
}

/// Probe that filter construction succeeds for the given mode.
///
/// Constructs (but does not load) a filter in the parent process. This confirms
/// that the libseccomp C library is functional before we fork.
#[cfg(feature = "seccomp")]
fn probe_filter(_mode: &PolicyMode) -> Result<(), String> {
    use libseccomp::{ScmpAction, ScmpFilterContext};
    ScmpFilterContext::new_filter(ScmpAction::KillProcess)
        .map(|_| ())
        .map_err(|e| format!("seccomp init: {e}"))
}

/// Classify the child's exit status, detecting SIGSYS (seccomp kill) in both forms:
///   1. `ExitStatus::signal() == SIGSYS` — raw signal visible to parent
///   2. `ExitStatus::code() == 128 + SIGSYS` — shell converted signal to exit code
#[cfg(feature = "seccomp")]
fn classify_exit_status(output: &std::process::Output) -> SandboxResult {
    use std::os::unix::process::ExitStatusExt;

    let sigsys = libc::SIGSYS;

    // Path 1: child terminated by signal directly.
    if let Some(sig) = output.status.signal() {
        if sig == sigsys {
            return Err(SandboxError::KilledByFilter {
                exit_code: -(sigsys),
            });
        }
    }

    // Path 2: sh caught SIGSYS and exited with 128 + signal.
    if let Some(code) = output.status.code() {
        if code == 128 + sigsys {
            return Err(SandboxError::KilledByFilter { exit_code: code });
        }
    }

    Ok(super::SandboxOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: output.status.code().unwrap_or(-1),
    })
}

/// Encode `PolicyMode` as a single byte for fork-boundary transfer.
/// 0 = ReadOnly, 1 = WorkspaceWrite. FullAccess never reaches this path.
#[cfg(feature = "seccomp")]
fn mode_byte(mode: &PolicyMode) -> u8 {
    match mode {
        PolicyMode::ReadOnly => 0,
        PolicyMode::WorkspaceWrite => 1,
        PolicyMode::FullAccess => 255,
    }
}

/// Decode the mode byte; unknown bytes default to the most restrictive mode.
#[cfg(feature = "seccomp")]
fn decode_mode_byte(byte: u8) -> PolicyMode {
    match byte {
        1 => PolicyMode::WorkspaceWrite,
        _ => PolicyMode::ReadOnly,
    }
}

/// Build and load the seccomp allowlist in the child process (called in pre_exec).
///
/// # Argument filtering
///
/// For `ReadOnly`:
/// - `open(path, flags)` and `openat(dfd, path, flags)` are allowed only when
///   `(flags & O_ACCMODE) == O_RDONLY`. Uses `ScmpCompareOp::MaskedEqual(O_ACCMODE)`
///   with datum `O_RDONLY` to enforce this. Blocks `O_WRONLY`, `O_RDWR`, `O_TRUNC`.
/// - `write(fd, ...)` and `writev(fd, ...)` are allowed only for fd ≤ 2
///   (stdin=0, stdout=1, stderr=2). Uses `ScmpCompareOp::LessOrEqual` with datum 2.
///
/// For `WorkspaceWrite`, both syscalls are unrestricted (path-level boundary is
/// enforced by the policy engine and validators before execution).
#[cfg(feature = "seccomp")]
fn apply_filter_in_child(mode: &PolicyMode) -> Result<(), String> {
    use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};

    // Default action: kill the process on any syscall not explicitly allowed.
    let mut filter = ScmpFilterContext::new_filter(ScmpAction::KillProcess)
        .map_err(|e| format!("seccomp init: {e}"))?;

    // ── Always-allowed: process lifecycle, memory, signals, identity ──────────
    // These are required by `sh` itself and safe in all modes.
    const ALWAYS_ALLOWED: &[&str] = &[
        // Process lifecycle
        "exit_group", "exit",
        "execve", "execveat",
        "getpid", "gettid", "getppid", "getpgrp", "setsid",
        "getuid", "getgid", "geteuid", "getegid",
        // Memory
        "brk", "mmap", "mmap2", "munmap", "mprotect", "mremap", "madvise",
        // Signals
        "rt_sigreturn", "rt_sigaction", "rt_sigprocmask", "rt_sigpending",
        "sigaltstack",
        // Threading / sync
        "futex", "futex_time64",
        "set_tid_address", "set_robust_list",
        // System info (read-only kernel interface)
        "uname", "arch_prctl",
        // File descriptor management (no open; handled separately with arg filter)
        "close", "dup", "dup2", "dup3",
        "fcntl", "fcntl64",
        // File metadata (read-only)
        "stat", "stat64", "fstat", "fstat64", "lstat", "lstat64",
        "statx", "newfstatat",
        // Pipes — needed by sh for pipelines
        "pipe", "pipe2",
        // Process wait — needed by sh to reap child processes
        "wait4", "waitpid", "waitid",
        // I/O multiplexing
        "poll", "ppoll", "select", "pselect6",
        "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
        // Timing
        "nanosleep", "clock_nanosleep", "clock_gettime", "gettimeofday",
        // Directory / path traversal (read metadata)
        "getcwd", "readlink", "readlinkat",
        "getdents", "getdents64",
        "lseek", "llseek",
        // Read data
        "read", "pread64", "readv", "preadv", "preadv2",
        // ioctl: needed by sh for tty/terminal operations
        "ioctl",
    ];
    for &name in ALWAYS_ALLOWED {
        if let Ok(sc) = ScmpSyscall::from_name(name) {
            filter
                .add_rule(ScmpAction::Allow, sc)
                .map_err(|e| format!("add_rule({name}): {e}"))?;
        }
    }

    // ── open / openat: argument-filtered for ReadOnly ─────────────────────────
    //
    // O_ACCMODE = 0x3 — masks the two low-order access-mode bits.
    // O_RDONLY  = 0x0 — value when only read access is requested.
    //
    // ScmpCompareOp::MaskedEqual(mask) checks: (arg & mask) == datum.
    // We use mask = O_ACCMODE, datum = O_RDONLY to allow only read-only opens.
    //
    // syscall arg indices (0-based):
    //   open(pathname, flags, mode):          flags = arg[1]
    //   openat(dirfd, pathname, flags, mode): flags = arg[2]
    let o_accmode = libc::O_ACCMODE as u64;
    let o_rdonly = libc::O_RDONLY as u64;

    if let Ok(sc) = ScmpSyscall::from_name("open") {
        let cmp = match mode {
            PolicyMode::ReadOnly => Some(ScmpArgCompare::new(
                1,
                ScmpCompareOp::MaskedEqual(o_accmode),
                o_rdonly,
            )),
            _ => None,
        };
        match cmp {
            Some(c) => filter
                .add_rule_conditional(ScmpAction::Allow, sc, &[c])
                .map_err(|e| format!("add_rule(open O_RDONLY): {e}"))?,
            None => filter
                .add_rule(ScmpAction::Allow, sc)
                .map_err(|e| format!("add_rule(open): {e}"))?,
        }
    }

    if let Ok(sc) = ScmpSyscall::from_name("openat") {
        let cmp = match mode {
            PolicyMode::ReadOnly => Some(ScmpArgCompare::new(
                2,
                ScmpCompareOp::MaskedEqual(o_accmode),
                o_rdonly,
            )),
            _ => None,
        };
        match cmp {
            Some(c) => filter
                .add_rule_conditional(ScmpAction::Allow, sc, &[c])
                .map_err(|e| format!("add_rule(openat O_RDONLY): {e}"))?,
            None => filter
                .add_rule(ScmpAction::Allow, sc)
                .map_err(|e| format!("add_rule(openat): {e}"))?,
        }
    }

    // ── write / writev: argument-filtered for ReadOnly ────────────────────────
    //
    // In ReadOnly mode the child must still write to stdout/stderr (fd 0, 1, 2).
    // We allow write/writev only when fd ≤ 2.
    // ScmpCompareOp::LessOrEqual with datum 2 enforces this on arg[0] (fd).
    let fd_stdout_err: u64 = 2;

    if let Ok(sc) = ScmpSyscall::from_name("write") {
        match mode {
            PolicyMode::ReadOnly => {
                let cmp = ScmpArgCompare::new(0, ScmpCompareOp::LessOrEqual, fd_stdout_err);
                filter
                    .add_rule_conditional(ScmpAction::Allow, sc, &[cmp])
                    .map_err(|e| format!("add_rule(write fd≤2): {e}"))?;
            }
            _ => {
                filter
                    .add_rule(ScmpAction::Allow, sc)
                    .map_err(|e| format!("add_rule(write): {e}"))?;
            }
        }
    }

    if let Ok(sc) = ScmpSyscall::from_name("writev") {
        match mode {
            PolicyMode::ReadOnly => {
                let cmp = ScmpArgCompare::new(0, ScmpCompareOp::LessOrEqual, fd_stdout_err);
                filter
                    .add_rule_conditional(ScmpAction::Allow, sc, &[cmp])
                    .map_err(|e| format!("add_rule(writev fd≤2): {e}"))?;
            }
            _ => {
                filter
                    .add_rule(ScmpAction::Allow, sc)
                    .map_err(|e| format!("add_rule(writev): {e}"))?;
            }
        }
    }

    // ── WorkspaceWrite-only syscalls ──────────────────────────────────────────
    if matches!(mode, PolicyMode::WorkspaceWrite) {
        const WRITE_ONLY: &[&str] = &[
            // File creation / destruction
            "creat",
            "unlink", "unlinkat",
            "rename", "renameat", "renameat2",
            "mkdir", "mkdirat",
            "rmdir",
            // File content modification
            "ftruncate", "ftruncate64",
            "truncate", "truncate64",
            "fallocate",
            // Metadata modification
            "chmod", "fchmod", "fchmodat",
            "chown", "fchown", "fchownat", "lchown",
            // Hard / symbolic links
            "symlink", "symlinkat",
            "link", "linkat",
        ];
        for &name in WRITE_ONLY {
            if let Ok(sc) = ScmpSyscall::from_name(name) {
                filter
                    .add_rule(ScmpAction::Allow, sc)
                    .map_err(|e| format!("add_rule({name}): {e}"))?;
            }
        }
    }

    filter.load().map_err(|e| format!("filter load: {e}"))?;
    Ok(())
}

// ── Fallback (seccomp feature not enabled) ────────────────────────────────────

/// Called when the crate is compiled *without* the `seccomp` feature.
///
/// **Security note:** this path provides **no OS-level syscall isolation**.
/// It falls back to `NoopSandbox`. Always enable the `seccomp` feature and
/// use `SeccompSandbox::strict()` for production deployments on Linux.
#[cfg(not(feature = "seccomp"))]
fn execute_with_seccomp(command: &str, context: &SandboxContext, strict: bool) -> SandboxResult {
    if strict {
        return Err(SandboxError::FilterSetup(
            "seccomp feature is not compiled in — \
             recompile with `--features agent-guard-sandbox/seccomp`. \
             No OS-level isolation is available."
                .to_string(),
        ));
    }
    eprintln!(
        "[agent-guard] WARN: SeccompSandbox compiled without `seccomp` feature. \
         Falling back to NoopSandbox — NO OS-LEVEL ISOLATION IN EFFECT. \
         This is UNSAFE for production."
    );
    NoopSandbox.execute(command, context)
}
