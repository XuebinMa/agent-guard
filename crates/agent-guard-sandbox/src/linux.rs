//! Linux seccomp-bpf sandbox.

#[cfg(target_os = "linux")]
use crate::process::{configure_process_group, wait_for_child};
#[cfg(all(target_os = "linux", feature = "seccomp"))]
use crate::seccomp_rules::{
    preflight_required_syscalls_with, COMMON_DENY_SYSCALLS, NETWORK_DENY_SYSCALLS,
    READ_ONLY_DENY_SYSCALLS, READ_ONLY_WRITE_FLAG_DENIES,
};
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
/// in the child process before `exec`. Without native support it fails closed;
/// an unfiltered compatibility shell must never report this backend as active.
pub struct SeccompSandbox;

impl SeccompSandbox {
    pub fn new() -> Self {
        Self
    }

    /// Compatibility constructor retained for callers that previously opted
    /// into strict mode. All seccomp instances are now fail-closed.
    pub fn strict() -> Self {
        Self
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
            // Static capability metadata is sandbox-wide rather than per-mode:
            // writes are available in workspace_write / full_access modes.
            filesystem_write_workspace: true,
            // Seccomp is path-agnostic, so workspace_write can still write
            // outside the workspace unless validators or Landlock tighten it.
            filesystem_write_global: true,
            // FullAccess intentionally skips the filter, so outbound networking
            // remains available in at least one supported mode.
            network_outbound_any: true,
            network_outbound_internet: true,
            network_outbound_local: true,
            child_process_spawn: true,
            registry_write: false,
        }
    }

    fn execute(&self, command: &str, context: &SandboxContext) -> SandboxResult {
        execute_with_seccomp(command, context)
    }

    fn health_check(&self, context: &SandboxContext) -> SandboxResult {
        #[cfg(all(target_os = "linux", feature = "seccomp"))]
        {
            let touch = ["/usr/bin/touch", "/bin/touch"]
                .into_iter()
                .find(|candidate| std::path::Path::new(candidate).is_file())
                .ok_or_else(|| {
                    SandboxError::ExecutionFailed(
                        "seccomp negative health probe requires /usr/bin/touch or /bin/touch"
                            .to_string(),
                    )
                })?;
            let probe = SeccompHealthProbeDir::create()?;
            let control_marker = probe.root.join("control");
            let control = Command::new(touch)
                .arg(&control_marker)
                .status()
                .map_err(|error| {
                    SandboxError::ExecutionFailed(format!(
                        "seccomp health probe control command failed: {error}"
                    ))
                })?;
            if !control.success() || !control_marker.is_file() {
                return Err(SandboxError::ExecutionFailed(
                    "seccomp health probe could not create its unsandboxed control file"
                        .to_string(),
                ));
            }
            std::fs::remove_file(&control_marker).map_err(|error| {
                SandboxError::ExecutionFailed(format!(
                    "seccomp health probe could not remove its control file: {error}"
                ))
            })?;

            let marker_path = probe.root.join("blocked");
            let mut probe_context = context.clone();
            probe_context.mode = PolicyMode::ReadOnly;
            probe_context.working_directory = probe.root.clone();
            let result = self.execute(&format!("{touch} blocked"), &probe_context);
            let blocked = match result {
                Err(SandboxError::KilledByFilter { .. }) => true,
                Err(error) => return Err(error),
                Ok(output) => output.exit_code != 0,
            };
            let marker_exists = marker_path.exists();

            if !blocked || marker_exists {
                return Err(SandboxError::ExecutionFailed(
                    "seccomp health probe unexpectedly allowed a read-only file creation"
                        .to_string(),
                ));
            }

            Ok(SandboxOutput {
                stdout: "seccomp negative write probe was blocked\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            })
        }

        #[cfg(not(all(target_os = "linux", feature = "seccomp")))]
        {
            self.execute("echo 1", context)
        }
    }

    fn is_available(&self) -> bool {
        cfg!(all(target_os = "linux", feature = "seccomp"))
    }
}

#[cfg(all(target_os = "linux", feature = "seccomp"))]
struct SeccompHealthProbeDir {
    root: std::path::PathBuf,
}

#[cfg(all(target_os = "linux", feature = "seccomp"))]
impl SeccompHealthProbeDir {
    fn create() -> Result<Self, SandboxError> {
        use std::io::ErrorKind;
        use std::sync::atomic::{AtomicU64, Ordering};

        static PROBE_ID: AtomicU64 = AtomicU64::new(0);
        for _ in 0..32 {
            let id = PROBE_ID.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "agent-guard-seccomp-health-{}-{id}",
                std::process::id()
            ));
            match std::fs::create_dir(&root) {
                Ok(()) => return Ok(Self { root }),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(SandboxError::ExecutionFailed(format!(
                        "seccomp health probe could not create a private directory: {error}"
                    )))
                }
            }
        }

        Err(SandboxError::ExecutionFailed(
            "seccomp health probe could not reserve a unique private directory".to_string(),
        ))
    }
}

#[cfg(all(target_os = "linux", feature = "seccomp"))]
impl Drop for SeccompHealthProbeDir {
    fn drop(&mut self) {
        for name in ["control", "blocked"] {
            let _ = std::fs::remove_file(self.root.join(name));
        }
        let _ = std::fs::remove_dir(&self.root);
    }
}

fn execute_with_seccomp(command: &str, context: &SandboxContext) -> SandboxResult {
    #[cfg(target_os = "linux")]
    {
        #[cfg(feature = "seccomp")]
        {
            execute_with_native_seccomp(command, context)
        }

        #[cfg(not(feature = "seccomp"))]
        {
            Err(SandboxError::FilterSetup(
                "native Seccomp-BPF support requires the 'seccomp' Cargo feature and libseccomp at build time".to_string(),
            ))
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
    let mut shell = Command::new("sh");
    configure_process_group(&mut shell);
    let child = shell
        .arg("-c")
        .arg(command)
        .current_dir(&context.working_directory)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| SandboxError::ExecutionFailed(format!("Failed to spawn process: {}", e)))?;

    finish_child(child, context.timeout_ms)
}

#[cfg(all(target_os = "linux", feature = "seccomp"))]
fn execute_with_native_seccomp(command: &str, context: &SandboxContext) -> SandboxResult {
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
    configure_process_group(&mut child);

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
                return Err(SandboxError::FilterSetup(format!(
                    "Seccomp filter setup failed: {}",
                    message
                )));
            }

            return Err(SandboxError::ExecutionFailed(format!(
                "Failed to spawn process: {}",
                message
            )));
        }
    };

    finish_child(child, context.timeout_ms)
}

#[cfg(target_os = "linux")]
fn finish_child(child: std::process::Child, timeout_ms: Option<u64>) -> SandboxResult {
    let output = wait_for_child(child, timeout_ms)?;
    let exit_status = output.status;

    if exit_status.signal() == Some(libc::SIGSYS) {
        return Err(SandboxError::KilledByFilter {
            exit_code: libc::SIGSYS,
        });
    }

    Ok(SandboxOutput {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: exit_status.code().unwrap_or(-1),
    })
}

#[cfg(all(target_os = "linux", feature = "seccomp"))]
fn apply_seccomp_rules(mode: &PolicyMode) -> Result<(), String> {
    // Resolve the complete required rule set before constructing/loading the
    // filter. A missing name is a setup failure, not permission to run with a
    // silently smaller deny set (issue #161).
    preflight_required_syscalls_with(mode, ScmpSyscall::from_name)?;

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
    for name in NETWORK_DENY_SYSCALLS {
        add_deny_rule(filter, name)?;
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "seccomp"))]
fn add_common_dangerous_syscall_denies(filter: &mut ScmpFilterContext) -> Result<(), String> {
    for name in COMMON_DENY_SYSCALLS {
        add_deny_rule(filter, name)?;
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "seccomp"))]
fn add_read_only_write_denies(filter: &mut ScmpFilterContext) -> Result<(), String> {
    for &(syscall, arg_index) in READ_ONLY_WRITE_FLAG_DENIES {
        add_write_flag_denies(filter, syscall, arg_index)?;
    }

    for name in READ_ONLY_DENY_SYSCALLS {
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
    let syscall = resolve_syscall(syscall_name)?;
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
    let syscall = resolve_syscall(syscall_name)?;

    filter
        .add_rule(ScmpAction::Errno(libc::EPERM), syscall)
        .map_err(|e| format!("failed to add deny rule for {syscall_name}: {e}"))
}

#[cfg(all(target_os = "linux", feature = "seccomp"))]
fn resolve_syscall(name: &str) -> Result<ScmpSyscall, String> {
    crate::seccomp_rules::resolve_required_syscall_with(name, ScmpSyscall::from_name)
}

#[cfg(all(test, target_os = "linux", not(feature = "seccomp")))]
mod no_feature_tests {
    use super::SeccompSandbox;
    use crate::{Sandbox, SandboxContext, SandboxError};
    use agent_guard_core::PolicyMode;

    #[test]
    fn seccomp_without_native_feature_never_runs_an_unfiltered_compat_shell() {
        let sandbox = SeccompSandbox::new();
        assert!(!sandbox.is_available());
        let context = SandboxContext {
            mode: PolicyMode::ReadOnly,
            working_directory: std::env::current_dir().expect("current directory"),
            timeout_ms: Some(1_000),
        };

        assert!(matches!(
            sandbox.execute("echo must-not-run", &context),
            Err(SandboxError::FilterSetup(_))
        ));
    }
}
