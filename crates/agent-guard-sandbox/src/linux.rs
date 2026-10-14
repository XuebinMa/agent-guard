//! Linux seccomp-bpf sandbox.

#[cfg(all(target_os = "linux", feature = "seccomp"))]
use crate::process::{configure_process_group, wait_for_child};
#[cfg(all(target_os = "linux", feature = "seccomp"))]
use crate::SandboxOutput;
use crate::{Sandbox, SandboxCapabilities, SandboxContext, SandboxError, SandboxResult};
#[cfg(all(target_os = "linux", feature = "seccomp"))]
use agent_guard_core::PolicyMode;
#[cfg(all(target_os = "linux", feature = "seccomp"))]
use std::os::unix::process::ExitStatusExt;
#[cfg(all(target_os = "linux", feature = "seccomp"))]
use std::process::Command;

#[cfg(all(target_os = "linux", feature = "seccomp"))]
mod native_seccomp;

#[cfg(all(test, target_os = "linux", feature = "seccomp"))]
#[path = "linux/native_tests.rs"]
mod native_tests;

#[cfg(all(target_os = "linux", feature = "seccomp"))]
#[derive(Clone, Copy, Default)]
struct SetupOptions {
    #[cfg(test)]
    fault: Option<SetupFault>,
}

#[cfg(all(test, target_os = "linux", feature = "seccomp"))]
#[derive(Clone, Copy)]
enum SetupFault {
    MissingSyscall,
    InvalidFilter,
    NoNewPrivileges,
}

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

fn execute_with_seccomp(_command: &str, _context: &SandboxContext) -> SandboxResult {
    #[cfg(target_os = "linux")]
    {
        #[cfg(feature = "seccomp")]
        {
            execute_with_native_seccomp(_command, _context)
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

#[cfg(all(target_os = "linux", feature = "seccomp"))]
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
    execute_with_native_seccomp_options(command, context, SetupOptions::default())
}

#[cfg(all(target_os = "linux", feature = "seccomp"))]
fn execute_with_native_seccomp_options(
    command: &str,
    context: &SandboxContext,
    options: SetupOptions,
) -> SandboxResult {
    if matches!(context.mode, PolicyMode::FullAccess) {
        return execute_compat_shell(command, context);
    }

    // Resolve names and compile BPF in the parent before fork. No libseccomp
    // state or allocator-dependent preparation crosses into pre_exec.
    let filter = native_seccomp::prepare_filter(&context.mode, options)
        .map_err(SandboxError::FilterSetup)?;
    native_seccomp::execute_prepared(command, context, filter, options)
}

#[cfg(all(target_os = "linux", feature = "seccomp"))]
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
