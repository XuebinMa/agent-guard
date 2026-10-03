use crate::{Sandbox, SandboxCapabilities, SandboxContext, SandboxError, SandboxResult};

/// Disabled Windows AppContainer prototype.
///
/// The former implementation replaced the workspace DACL with one containing
/// only the AppContainer ACE and did not restore the original descriptor. It
/// also closed inherited pipe handles both manually and through RAII guards.
/// Until Windows integration tests prove byte-for-byte DACL restoration on
/// every success and failure path, advertising that code as an active sandbox
/// would be less safe than refusing it explicitly.
pub struct AppContainerSandbox;

const DISABLED_REASON: &str = "AppContainer is disabled: the prototype cannot yet prove exact workspace DACL restoration on every exit path";

impl Sandbox for AppContainerSandbox {
    fn name(&self) -> &'static str {
        "AppContainer (disabled)"
    }

    fn sandbox_type(&self) -> &'static str {
        "windows-appcontainer"
    }

    fn capabilities(&self) -> SandboxCapabilities {
        // This backend never executes. Report no containment promises so a
        // diagnostic consumer cannot mistake the prototype's intended design
        // for an active host boundary.
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

    fn execute(&self, _command: &str, _context: &SandboxContext) -> SandboxResult {
        Err(SandboxError::NotAvailable(DISABLED_REASON.to_string()))
    }

    fn is_available(&self) -> bool {
        false
    }

    fn availability_note(&self) -> Option<String> {
        Some(DISABLED_REASON.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_guard_core::PolicyMode;

    #[test]
    fn disabled_backend_never_executes_or_claims_availability() {
        let sandbox = AppContainerSandbox;
        let context = SandboxContext {
            mode: PolicyMode::WorkspaceWrite,
            working_directory: std::env::temp_dir(),
            timeout_ms: Some(1_000),
        };

        assert!(!sandbox.is_available());
        let error = sandbox
            .execute("echo must-not-run", &context)
            .expect_err("disabled AppContainer must fail closed");
        assert!(error.to_string().contains("DACL restoration"));
    }
}
