//! Linux Landlock sandbox for filesystem write isolation.
//!
//! Uses Linux Landlock LSM ABI v3 (kernel 6.2+) to enforce mode-aware
//! filesystem writes. Network restriction requires Landlock ABI v4 and is not
//! yet implemented.

#[cfg(target_os = "linux")]
use crate::process::{configure_process_group, wait_for_child};
#[cfg(target_os = "linux")]
use crate::SandboxOutput;
use crate::{Sandbox, SandboxCapabilities, SandboxContext, SandboxError, SandboxResult};
#[cfg(any(target_os = "linux", test))]
use agent_guard_core::PolicyMode;
#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LandlockWriteScope {
    None,
    Workspace,
    Global,
}

#[cfg(any(target_os = "linux", test))]
fn write_scope_for_mode(mode: &PolicyMode) -> LandlockWriteScope {
    match mode {
        PolicyMode::Blocked | PolicyMode::ReadOnly => LandlockWriteScope::None,
        PolicyMode::WorkspaceWrite => LandlockWriteScope::Workspace,
        PolicyMode::FullAccess => LandlockWriteScope::Global,
    }
}

/// Landlock-based sandbox enforcing mode-aware filesystem write restrictions.
///
/// Requires Landlock ABI v3 (upstream Linux 6.2+) with Landlock enabled.
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
            // Static metadata spans every PolicyMode. Restricted modes are
            // tightened at execute time, while FullAccess permits global
            // writes by definition.
            filesystem_write_global: true,
            network_outbound_any: true, // NOT enforced (needs ABI v4)
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
    use std::os::unix::process::CommandExt;

    // Creating a ruleset is not enough to prove that the host lets this
    // process enter a Landlock domain: an outer seccomp policy may still deny
    // `landlock_restrict_self(2)`. Probe the complete setup in a disposable
    // child so `is_available()` never irreversibly restricts the caller.
    let mut probe = Command::new("sh");
    probe
        .arg("-c")
        .arg("exit 0")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    // SAFETY: the callback only prepares the child immediately before exec;
    // the same audited setup path is used for real sandbox executions.
    unsafe {
        probe.pre_exec(|| {
            apply_landlock_rules(std::path::Path::new("/"), &PolicyMode::ReadOnly)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))
        });
    }

    probe.status().is_ok_and(|status| status.success())
}

#[cfg(target_os = "linux")]
fn execute_with_landlock(command: &str, context: &SandboxContext) -> SandboxResult {
    use std::os::unix::process::CommandExt;

    let resolved_dir = context.working_directory.canonicalize().map_err(|e| {
        SandboxError::ExecutionFailed(format!("Failed to resolve workspace: {}", e))
    })?;

    let workspace_path = resolved_dir.clone();
    let mode = context.mode.clone();

    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(command)
        .current_dir(&resolved_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    configure_process_group(&mut cmd);

    // Apply Landlock restrictions in the child process before exec
    unsafe {
        cmd.pre_exec(move || {
            apply_landlock_rules(&workspace_path, &mode)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))
        });
    }

    let child = cmd.spawn().map_err(|e| {
        let msg = e.to_string();
        if e.kind() == std::io::ErrorKind::PermissionDenied
            || msg.contains("PermissionDenied")
            || msg.contains("landlock")
        {
            SandboxError::FilterSetup(format!("Landlock setup failed: {}", msg))
        } else {
            SandboxError::ExecutionFailed(format!("Failed to spawn process: {}", msg))
        }
    })?;

    let output = wait_for_child(child, context.timeout_ms)?;

    Ok(SandboxOutput {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code().unwrap_or(-1),
    })
}

#[cfg(target_os = "linux")]
fn apply_landlock_rules(workspace: &std::path::Path, mode: &PolicyMode) -> Result<(), String> {
    use landlock::{
        Access, AccessFs, CompatLevel, Compatible, LandlockStatus, PathBeneath, PathFd, Ruleset,
        RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
    };

    // ABI v3 is the first ABI that handles truncate(2), ftruncate(2), and
    // open(2) with O_TRUNC. Advertising path-aware write isolation on V1/V2
    // leaves those mutations outside the ruleset, so V3 is a hard minimum.
    let abi = ABI::V3;

    // HardRequirement turns an older/partially compatible host into setup
    // failure instead of silently dropping rights from the boundary.
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| format!("Failed to create Landlock ruleset: {}", e))?
        .create()
        .map_err(|e| format!("Failed to create Landlock ruleset: {}", e))?;

    // Reads and execution remain available globally. Write rights are derived
    // from the effective policy mode rather than granted to the workspace
    // unconditionally.
    let read_access = AccessFs::from_read(abi);
    let root_access = match write_scope_for_mode(mode) {
        LandlockWriteScope::Global => AccessFs::from_all(abi),
        LandlockWriteScope::None | LandlockWriteScope::Workspace => read_access,
    };
    let root_fd = PathFd::new("/").map_err(|e| format!("Failed to open /: {}", e))?;
    ruleset = ruleset
        .add_rule(PathBeneath::new(root_fd, root_access))
        .map_err(|e| format!("Failed to add read rule for /: {}", e))?;

    if write_scope_for_mode(mode) == LandlockWriteScope::Workspace {
        let workspace_fd = PathFd::new(workspace)
            .map_err(|e| format!("Failed to open workspace '{}': {}", workspace.display(), e))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(workspace_fd, AccessFs::from_all(abi)))
            .map_err(|e| format!("Failed to add workspace rule: {}", e))?;
    }

    // Enforce: restrict this process
    let status = ruleset
        .restrict_self()
        .map_err(|e| format!("Failed to enforce Landlock: {}", e))?;

    match (status.ruleset, status.no_new_privs, status.landlock) {
        (RulesetStatus::FullyEnforced, true, LandlockStatus::Available { effective_abi, .. })
            if effective_abi >= abi =>
        {
            Ok(())
        }
        (RulesetStatus::PartiallyEnforced, _, _) => {
            Err("Landlock ruleset was only partially enforced; refusing execution".to_string())
        }
        (RulesetStatus::NotEnforced, _, _) => {
            Err("Landlock ruleset was not enforced by the kernel".to_string())
        }
        (RulesetStatus::FullyEnforced, false, _) => {
            Err("Landlock did not enforce no_new_privs; refusing execution".to_string())
        }
        (RulesetStatus::FullyEnforced, true, landlock) => Err(format!(
            "Landlock ABI v3 is required, but enforcement reported {landlock:?}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{write_scope_for_mode, LandlockWriteScope};
    use agent_guard_core::PolicyMode;

    #[test]
    fn policy_modes_map_to_their_exact_write_scope() {
        assert_eq!(
            write_scope_for_mode(&PolicyMode::Blocked),
            LandlockWriteScope::None
        );
        assert_eq!(
            write_scope_for_mode(&PolicyMode::ReadOnly),
            LandlockWriteScope::None
        );
        assert_eq!(
            write_scope_for_mode(&PolicyMode::WorkspaceWrite),
            LandlockWriteScope::Workspace
        );
        assert_eq!(
            write_scope_for_mode(&PolicyMode::FullAccess),
            LandlockWriteScope::Global
        );
    }
}
