//! Linux Landlock sandbox for filesystem write isolation.
//!
//! Uses Linux Landlock LSM (kernel 5.13+) to restrict filesystem writes
//! to the workspace directory only. Network restriction requires Landlock
//! ABI v4 and is not yet implemented.

#[cfg(target_os = "linux")]
use crate::SandboxOutput;
use crate::{Sandbox, SandboxCapabilities, SandboxContext, SandboxError, SandboxResult};
#[cfg(target_os = "linux")]
use std::process::Command;

/// Landlock-based sandbox restricting filesystem writes to the workspace directory.
///
/// Requires Linux kernel 5.13+ with Landlock enabled.
/// Currently enforces filesystem write isolation only.
pub struct LandlockSandbox;

impl Sandbox for LandlockSandbox {
    fn name(&self) -> &'static str {
        "landlock"
    }

    fn sandbox_type(&self) -> &'static str {
        "linux-landlock"
    }

    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities {
            filesystem_read_workspace: true,
            filesystem_read_global: true,
            filesystem_write_workspace: true,
            filesystem_write_global: false, // ENFORCED: writes restricted to workspace
            network_outbound_any: true,     // NOT enforced (needs ABI v4)
            network_outbound_internet: true,
            network_outbound_local: true,
            child_process_spawn: true,
            registry_write: false,
        }
    }

    #[cfg(target_os = "linux")]
    fn execute(&self, command: &str, context: &SandboxContext) -> SandboxResult {
        execute_with_landlock(command, context)
    }

    #[cfg(not(target_os = "linux"))]
    fn execute(&self, _command: &str, _context: &SandboxContext) -> SandboxResult {
        Err(SandboxError::NotAvailable(
            "Landlock is only available on Linux".to_string(),
        ))
    }

    fn is_available(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            is_landlock_supported()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

#[cfg(target_os = "linux")]
fn is_landlock_supported() -> bool {
    use landlock::{AccessFs, Ruleset, RulesetAttr, ABI};

    Ruleset::default()
        .handle_access(AccessFs::from_all(ABI::V1))
        .and_then(|ruleset| ruleset.create())
        .is_ok()
}

#[cfg(target_os = "linux")]
fn execute_with_landlock(command: &str, context: &SandboxContext) -> SandboxResult {
    use std::os::unix::process::CommandExt;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let resolved_dir = context.working_directory.canonicalize().map_err(|e| {
        SandboxError::ExecutionFailed(format!("Failed to resolve workspace: {}", e))
    })?;

    let workspace_path = resolved_dir.clone();

    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(command)
        .current_dir(&resolved_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    // Apply Landlock restrictions in the child process before exec
    unsafe {
        cmd.pre_exec(move || {
            apply_landlock_rules(&workspace_path)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))
        });
    }

    let mut child = cmd.spawn().map_err(|e| {
        let msg = e.to_string();
        if msg.contains("PermissionDenied") || msg.contains("landlock") {
            SandboxError::FilterSetup(format!("Landlock setup failed: {}", msg))
        } else {
            SandboxError::ExecutionFailed(format!("Failed to spawn process: {}", msg))
        }
    })?;

    // Timeout handling (same pattern as macos.rs)
    if let Some(timeout_ms) = context.timeout_ms {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(timeout_ms));
            let _ = tx.send(());
        });

        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let output = child
                        .wait_with_output()
                        .map_err(|e| SandboxError::ExecutionFailed(e.to_string()))?;
                    return Ok(SandboxOutput {
                        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                        exit_code: status.code().unwrap_or(-1),
                    });
                }
                Ok(None) => {
                    if rx.try_recv().is_ok() {
                        let _ = child.kill();
                        let _ = child.wait(); // Prevent zombie
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

    Ok(SandboxOutput {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: output.status.code().unwrap_or(-1),
    })
}

#[cfg(target_os = "linux")]
fn apply_landlock_rules(workspace: &std::path::Path) -> Result<(), String> {
    use landlock::{
        Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus, ABI,
    };

    let abi = ABI::V1;

    // Build the ruleset: handle all filesystem access types
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| format!("Failed to create Landlock ruleset: {}", e))?
        .create()
        .map_err(|e| format!("Failed to create Landlock ruleset: {}", e))?;

    // Rule 1: Allow full read + execute access globally (from /)
    let read_access = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;
    let root_fd = PathFd::new("/").map_err(|e| format!("Failed to open /: {}", e))?;
    ruleset = ruleset
        .add_rule(PathBeneath::new(root_fd, read_access))
        .map_err(|e| format!("Failed to add read rule for /: {}", e))?;

    // Rule 2: Allow full access (read + write) within workspace
    let workspace_fd = PathFd::new(workspace)
        .map_err(|e| format!("Failed to open workspace '{}': {}", workspace.display(), e))?;
    ruleset = ruleset
        .add_rule(PathBeneath::new(workspace_fd, AccessFs::from_all(abi)))
        .map_err(|e| format!("Failed to add workspace rule: {}", e))?;

    // Enforce: restrict this process
    let status = ruleset
        .restrict_self()
        .map_err(|e| format!("Failed to enforce Landlock: {}", e))?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => Ok(()),
        RulesetStatus::PartiallyEnforced => {
            // Some rules may not be fully supported on older kernels
            // This is acceptable — partial enforcement is better than none
            Ok(())
        }
        RulesetStatus::NotEnforced => {
            Err("Landlock ruleset was not enforced by the kernel".to_string())
        }
    }
}
