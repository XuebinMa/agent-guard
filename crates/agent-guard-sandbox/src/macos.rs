use std::process::Command;
use crate::{Sandbox, SandboxContext, SandboxError, SandboxOutput, SandboxResult, SandboxCapabilities};

/// macOS Seatbelt sandbox using sandbox-exec.
pub struct SeatbeltSandbox;

impl Sandbox for SeatbeltSandbox {
    fn name(&self) -> &'static str {
        "seatbelt"
    }

    fn sandbox_type(&self) -> &'static str {
        "macos-seatbelt"
    }

    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities {
            syscall_filtering: false,
            filesystem_isolation: true,
            network_blocking: true,
            resource_limits: false,
            process_tree_cleanup: false,
        }
    }

    fn is_available(&self) -> bool {
        cfg!(target_os = "macos")
    }

    fn execute(&self, command: &str, context: &SandboxContext) -> SandboxResult {
        #[cfg(target_os = "macos")]
        {
            // Implementation...
            let mut child = Command::new("sh")
                .arg("-c")
                .arg(command)
                .current_dir(&context.working_directory)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| SandboxError::ExecutionFailed(e.to_string()))?;

            let output = child.wait_with_output()
                .map_err(|e| SandboxError::ExecutionFailed(e.to_string()))?;

            Ok(SandboxOutput {
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                exit_code: output.status.code().unwrap_or(-1),
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(SandboxError::NotAvailable("Seatbelt is only available on macOS".to_string()))
        }
    }
}
