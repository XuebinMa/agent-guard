use super::{Sandbox, SandboxContext, SandboxError, SandboxOutput, SandboxResult, SandboxCapabilities};

/// No-op sandbox — passthrough with no OS-level isolation.
pub struct NoopSandbox;

impl Sandbox for NoopSandbox {
    fn name(&self) -> &'static str {
        "noop"
    }

    fn sandbox_type(&self) -> &'static str {
        "none"
    }

    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities {
            syscall_filtering: false,
            filesystem_isolation: false,
            network_blocking: false,
            resource_limits: false,
            process_tree_cleanup: false,
        }
    }

    fn execute(&self, command: &str, context: &SandboxContext) -> SandboxResult {
        use std::process::Command;
        
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

    fn is_available(&self) -> bool {
        true
    }
}
