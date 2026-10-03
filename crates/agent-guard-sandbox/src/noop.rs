use super::{
    Sandbox, SandboxCapabilities, SandboxContext, SandboxError, SandboxOutput, SandboxResult,
};

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
            filesystem_read_workspace: true,
            filesystem_read_global: true,
            filesystem_write_workspace: true,
            filesystem_write_global: true,
            network_outbound_any: true,
            network_outbound_internet: true,
            network_outbound_local: true,
            child_process_spawn: true,
            registry_write: true,
        }
    }

    fn execute(&self, command: &str, context: &SandboxContext) -> SandboxResult {
        use crate::process::{configure_process_group, shell_command, wait_for_child};

        let mut command = shell_command(command);
        configure_process_group(&mut command);
        let child = command
            .current_dir(&context.working_directory)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| SandboxError::ExecutionFailed(e.to_string()))?;
        let output = wait_for_child(child, context.timeout_ms)?;

        Ok(SandboxOutput {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.status.code().unwrap_or(-1),
        })
    }

    fn is_available(&self) -> bool {
        true
    }
}
