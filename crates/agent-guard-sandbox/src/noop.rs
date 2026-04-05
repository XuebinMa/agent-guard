use super::{Sandbox, SandboxResult};

/// No-op sandbox — passes through execution without any isolation.
///
/// Suitable for local development, testing, and platforms where OS-level
/// sandboxing is not yet implemented (macOS, Windows).
/// Production deployments on Linux should swap this for a seccomp/namespaces-backed impl.
pub struct NoopSandbox;

impl Sandbox for NoopSandbox {
    fn name(&self) -> &'static str {
        "noop"
    }

    fn execute(&self, command: &str, _env: &[(&str, &str)]) -> SandboxResult {
        // NoopSandbox does not actually run anything — it is a stub that signals
        // "execution is the caller's responsibility."
        // The SDK layer (Guard) is expected to use this result to decide whether
        // to proceed with raw execution or delegate to a real sandbox.
        Ok(format!("[noop-sandbox] would execute: {}", command))
    }

    fn is_available(&self) -> bool {
        true
    }
}

impl NoopSandbox {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for NoopSandbox {
    fn default() -> Self {
        Self::new()
    }
}
