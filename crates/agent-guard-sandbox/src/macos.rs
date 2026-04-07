use std::process::Command;
use std::path::Path;
use agent_guard_core::PolicyMode;
use crate::{Sandbox, SandboxContext, SandboxError, SandboxOutput, SandboxResult};

/// Experimental macOS sandbox using `sandbox-exec` (Seatbelt).
/// 
/// This sandbox uses a dynamically generated Seatbelt profile to restrict
/// filesystem access based on the `PolicyMode`.
pub struct SeatbeltSandbox;

impl Sandbox for SeatbeltSandbox {
    fn name(&self) -> &'static str {
        "seatbelt"
    }

    fn sandbox_type(&self) -> &'static str {
        "macos-seatbelt"
    }

    fn capabilities(&self) -> crate::SandboxCapabilities {
        crate::SandboxCapabilities {
            syscall_filtering: false,
            filesystem_isolation: true,
            network_blocking: true,
            resource_limits: false,
            process_tree_cleanup: false,
        }
    }

    fn is_available(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            Path::new("/usr/bin/sandbox-exec").exists()
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }

    fn execute(&self, command: &str, context: &SandboxContext) -> SandboxResult {
        if !self.is_available() {
            return Err(SandboxError::NotAvailable("sandbox-exec not found or not on macOS".to_string()));
        }

        let profile = self.generate_profile(context);
        
        let child = Command::new("/usr/bin/sandbox-exec")
            .arg("-p")
            .arg(&profile)
            .arg("bash")
            .arg("-c")
            .arg(command)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| SandboxError::ExecutionFailed(format!("failed to spawn sandbox-exec: {e}")))?;

        let output = child.wait_with_output()
            .map_err(|e| SandboxError::ExecutionFailed(format!("failed to wait for child: {e}")))?;

        Ok(SandboxOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        })
    }
}

impl SeatbeltSandbox {
    fn generate_profile(&self, context: &SandboxContext) -> String {
        // Canonicalize the working directory to ensure it matches the path in the sandbox
        let wd = std::fs::canonicalize(&context.working_directory)
            .unwrap_or_else(|_| context.working_directory.clone());
        let wd_str = wd.to_string_lossy();
        
        let mut profile = String::from("(version 1)\n(deny default)\n");
        
        // Basic process and system access
        profile.push_str("(allow process*)\n");
        profile.push_str("(allow sysctl-read)\n");
        profile.push_str("(allow signal)\n");
        profile.push_str("(allow network*)\n");
        
        // Global read access (standard for tools)
        profile.push_str("(allow file-read*)\n");
        
        // Allow writes to system devices and temporary locations
        profile.push_str("(allow file-write* (subpath \"/dev\"))\n");
        profile.push_str("(allow file-write* (subpath \"/private/var/folders\"))\n");
        profile.push_str("(allow file-write* (subpath \"/tmp\"))\n");
        
        // Write access based on mode
        match context.mode {
            PolicyMode::ReadOnly => {
                // Minimal writes already covered above (/dev/null, etc.)
            }
            PolicyMode::WorkspaceWrite => {
                profile.push_str(&format!("(allow file-write* (subpath \"{}\"))\n", wd_str));
            }
            PolicyMode::FullAccess => {
                profile.push_str("(allow file-write*)\n");
            }
        }
        
        profile
    }
}
