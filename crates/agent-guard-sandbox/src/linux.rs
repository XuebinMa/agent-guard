//! Linux seccomp-bpf sandbox.

use crate::{
    Sandbox, SandboxCapabilities, SandboxContext, SandboxError, SandboxOutput, SandboxResult,
};
#[cfg(all(target_os = "linux", feature = "seccomp"))]
use agent_guard_core::PolicyMode;
#[cfg(all(target_os = "linux", feature = "seccomp"))]
use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

/// Linux seccomp-bpf sandbox.
///
/// With the `seccomp` feature enabled, this loads a native Seccomp-BPF filter
/// in the child process before `exec`. Without that feature, it falls back to
/// the compatibility shell wrapper.
pub struct SeccompSandbox {
    strict: bool,
}

impl SeccompSandbox {
    pub fn new() -> Self {
        Self { strict: false }
    }

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

    fn sandbox_type(&self) -> &'static str {
        "linux-seccomp"
    }

    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities {
            filesystem_read_workspace: true,
            filesystem_read_global: true,
            filesystem_write_workspace: true, // permitted in workspace_write / full_access modes
            filesystem_write_global: true, // seccomp is path-agnostic; validators enforce path policy
            network_outbound_any: true, // full_access mode intentionally leaves networking available
            network_outbound_internet: true,
            network_outbound_local: true,
            child_process_spawn: true,
            registry_write: false,
        }
    }

    fn execute(&self, command: &str, context: &SandboxContext) -> SandboxResult {
        execute_with_seccomp(command, context, self.strict)
    }

    fn is_available(&self) -> bool {
        cfg!(target_os = "linux")
    }
}

fn execute_with_seccomp(command: &str, context: &SandboxContext, strict: bool) -> SandboxResult {
    #[cfg(target_os = "linux")]
    {
        #[cfg(feature = "seccomp")]
        {
            execute_with_native_seccomp(command, context, strict)
        }

        #[cfg(not(feature = "seccomp"))]
        {
            if strict {
                Err(SandboxError::FilterSetup(
                    "native Seccomp-BPF support requires the 'seccomp' Cargo feature and libseccomp at build time".to_string(),
                ))
            } else {
                execute_compat_shell(command, context)
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(SandboxError::NotAvailable(
            "Seccomp is only available on Linux".to_string(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn execute_compat_shell(command: &str, context: &SandboxContext) -> SandboxResult {
    let child = Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(&context.working_directory)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| SandboxError::ExecutionFailed(format!("Failed to spawn process: {}", e)))?;

    wait_for_child(child, context.timeout_ms)
}

#[cfg(all(target_os = "linux", feature = "seccomp"))]
fn execute_with_native_seccomp(
    command: &str,
    context: &SandboxContext,
    strict: bool,
) -> SandboxResult {
    if matches!(context.mode, PolicyMode::FullAccess) {
        return execute_compat_shell(command, context);
    }

    let mode = context.mode.clone();
    let mut child = Command::new("sh");
    child
        .arg("-c")
        .arg(command)
        .current_dir(&context.working_directory)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    unsafe {
        child.pre_exec(move || {
            apply_seccomp_rules(&mode)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))
        });
    }

    let child = match child.spawn() {
        Ok(child) => child,
        Err(e) => {
            let message = e.to_string();
            if message.contains("seccomp") || e.kind() == std::io::ErrorKind::PermissionDenied {
                if strict {
                    return Err(SandboxError::FilterSetup(format!(
                        "Seccomp filter setup failed: {}",
                        message
                    )));
                }
                return execute_compat_shell(command, context);
            }

            return Err(SandboxError::ExecutionFailed(format!(
                "Failed to spawn process: {}",
                message
            )));
        }
    };

    wait_for_child(child, context.timeout_ms)
}

#[cfg(target_os = "linux")]
fn wait_for_child(mut child: std::process::Child, timeout_ms: Option<u64>) -> SandboxResult {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    if let Some(timeout_ms) = timeout_ms {
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            thread::sleep(Duration::from_millis(timeout_ms));
            let _ = tx.send(());
        });

        loop {
            match child.try_wait() {
                Ok(Some(_status)) => break,
                Ok(None) => {
                    if rx.try_recv().is_ok() {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(SandboxError::Timeout { ms: timeout_ms });
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(SandboxError::ExecutionFailed(e.to_string())),
            }
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|e| SandboxError::ExecutionFailed(e.to_string()))?;
    let exit_status = output.status;

    if exit_status.signal() == Some(libc::SIGSYS) {
        return Err(SandboxError::KilledByFilter {
            exit_code: libc::SIGSYS,
        });
    }

    Ok(SandboxOutput {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: exit_status.code().unwrap_or(-1),
    })
}

#[cfg(all(target_os = "linux", feature = "seccomp"))]
fn apply_seccomp_rules(mode: &PolicyMode) -> Result<(), String> {
    let mut filter = ScmpFilterContext::new_filter(ScmpAction::Allow)
        .map_err(|e| format!("failed to create seccomp filter: {e}"))?;
    filter
        .set_ctl_nnp(true)
        .map_err(|e| format!("failed to set no_new_privs: {e}"))?;

    add_network_denies(&mut filter)?;
    add_common_dangerous_syscall_denies(&mut filter)?;

    if matches!(mode, PolicyMode::ReadOnly) {
        add_read_only_write_denies(&mut filter)?;
    }

    filter
        .load()
        .map_err(|e| format!("failed to load seccomp filter: {e}"))?;
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "seccomp"))]
fn add_network_denies(filter: &mut ScmpFilterContext) -> Result<(), String> {
    for name in [
        "socket",
        "socketpair",
        "connect",
        "bind",
        "listen",
        "accept",
        "accept4",
        "sendto",
        "sendmsg",
        "sendmmsg",
        "recvfrom",
        "recvmsg",
        "recvmmsg",
        "shutdown",
        "setsockopt",
        "getsockopt",
    ] {
        add_deny_rule(filter, name)?;
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "seccomp"))]
fn add_common_dangerous_syscall_denies(filter: &mut ScmpFilterContext) -> Result<(), String> {
    for name in [
        "ptrace",
        "mount",
        "umount2",
        "swapon",
        "swapoff",
        "reboot",
        "kexec_load",
        "finit_module",
        "init_module",
        "delete_module",
        "bpf",
        "unshare",
        "setns",
    ] {
        add_deny_rule(filter, name)?;
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "seccomp"))]
fn add_read_only_write_denies(filter: &mut ScmpFilterContext) -> Result<(), String> {
    for (syscall, arg_index) in [("open", 1u32), ("openat", 2u32)] {
        add_write_flag_denies(filter, syscall, arg_index)?;
    }

    for name in [
        "creat",
        "truncate",
        "ftruncate",
        "mkdir",
        "mkdirat",
        "rmdir",
        "unlink",
        "unlinkat",
        "rename",
        "renameat",
        "renameat2",
        "link",
        "linkat",
        "symlink",
        "symlinkat",
        "mknod",
        "mknodat",
        "chmod",
        "fchmod",
        "fchmodat",
        "chown",
        "fchown",
        "fchownat",
        "lchown",
        "utime",
        "utimensat",
        "setxattr",
        "lsetxattr",
        "fsetxattr",
        "removexattr",
        "lremovexattr",
        "fremovexattr",
        "copy_file_range",
    ] {
        add_deny_rule(filter, name)?;
    }

    Ok(())
}

#[cfg(all(target_os = "linux", feature = "seccomp"))]
fn add_write_flag_denies(
    filter: &mut ScmpFilterContext,
    syscall_name: &str,
    arg_index: u32,
) -> Result<(), String> {
    let Some(syscall) = resolve_syscall(syscall_name)? else {
        return Ok(());
    };
    let deny = ScmpAction::Errno(libc::EPERM);
    let access_mode_mask = libc::O_ACCMODE as u64;

    filter
        .add_rule_conditional(
            deny,
            syscall,
            &[ScmpArgCompare::new(
                arg_index,
                ScmpCompareOp::MaskedEqual(access_mode_mask),
                libc::O_WRONLY as u64,
            )],
        )
        .map_err(|e| format!("failed to add {syscall_name} O_WRONLY deny rule: {e}"))?;

    filter
        .add_rule_conditional(
            deny,
            syscall,
            &[ScmpArgCompare::new(
                arg_index,
                ScmpCompareOp::MaskedEqual(access_mode_mask),
                libc::O_RDWR as u64,
            )],
        )
        .map_err(|e| format!("failed to add {syscall_name} O_RDWR deny rule: {e}"))?;

    for flag in [libc::O_CREAT, libc::O_TRUNC, libc::O_APPEND] {
        filter
            .add_rule_conditional(
                deny,
                syscall,
                &[ScmpArgCompare::new(
                    arg_index,
                    ScmpCompareOp::MaskedEqual(flag as u64),
                    flag as u64,
                )],
            )
            .map_err(|e| format!("failed to add {syscall_name} flag deny rule: {e}"))?;
    }

    Ok(())
}

#[cfg(all(target_os = "linux", feature = "seccomp"))]
fn add_deny_rule(filter: &mut ScmpFilterContext, syscall_name: &str) -> Result<(), String> {
    let Some(syscall) = resolve_syscall(syscall_name)? else {
        return Ok(());
    };

    filter
        .add_rule(ScmpAction::Errno(libc::EPERM), syscall)
        .map_err(|e| format!("failed to add deny rule for {syscall_name}: {e}"))
}

#[cfg(all(target_os = "linux", feature = "seccomp"))]
fn resolve_syscall(name: &str) -> Result<Option<ScmpSyscall>, String> {
    match ScmpSyscall::from_name(name) {
        Ok(syscall) => Ok(Some(syscall)),
        // Some older libseccomp builds do not recognize every syscall symbol
        // on every runner architecture. Skip those rules instead of failing the
        // whole sandbox setup.
        Err(e) if e.to_string().contains("Could not resolve syscall name") => Ok(None),
        Err(e) => Err(format!("failed to resolve syscall {name}: {e}")),
    }
}
