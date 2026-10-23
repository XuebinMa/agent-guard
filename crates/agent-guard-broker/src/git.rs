//! The broker's isolated Git execution context.
//!
//! The repository belongs to the agent. Its config, hooks and object-store
//! indirections are therefore input, never execution context. Every operation
//! that can contact a remote runs from a broker-owned temporary bare
//! repository containing a regular-file snapshot of the source refs and
//! primary object database.

mod command;
mod credentials;
mod process;
mod snapshot;
mod validate;

use std::path::PathBuf;
use std::time::Duration;

use thiserror::Error;

pub(crate) use snapshot::GitSnapshot;
pub use validate::validate_push_target;

#[derive(Debug, Error)]
pub enum GitError {
    #[error("git could not be run: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("git {command} failed with status {status:?}: {stderr}")]
    Failed {
        command: String,
        status: Option<i32>,
        stderr: String,
    },
    #[error("git push explicitly rejected the approved ref (status {status:?}): {stderr}")]
    Rejected { status: Option<i32>, stderr: String },
    #[error("git {command} produced output this did not expect: {detail}")]
    Unexpected { command: String, detail: String },
    #[error("broker Git boundary refused the repository: {detail}")]
    UnsafeRepository { detail: String },
    #[error("broker Git boundary refused its trusted config: {detail}")]
    UnsafeConfig { detail: String },
    #[error("broker Git boundary refused the remote: {detail}")]
    UnsafeRemote { detail: String },
    #[error("broker Git boundary refused the push target: {detail}")]
    InvalidTarget { detail: String },
    #[error("git {command} exceeded its {timeout_ms} ms operation budget")]
    TimedOut {
        command: String,
        timeout_ms: u64,
        started: bool,
    },
    #[error("git {command} exceeded the {limit_bytes} byte output limit")]
    OutputLimit { command: String, limit_bytes: u64 },
    #[error("git {command} process cleanup failed: {detail}")]
    CleanupFailed { command: String, detail: String },
}

/// Inputs trusted by the broker process rather than by the source repository.
#[derive(Debug, Clone, Default)]
pub struct BrokerGitOptions {
    /// A host-owned Git config. Only credential/http settings and
    /// `ssh.variant` are accepted, and the exact bytes are snapshotted before
    /// use.
    pub trusted_config: Option<PathBuf>,
    /// Local filesystem remotes are disabled in the product path. Tests and
    /// the self-contained demo opt in explicitly.
    pub allow_local_file_remote: bool,
}

/// The public broker context. Transaction and execution methods use these
/// strict options instead of reconstructing subprocess behavior ad hoc.
#[derive(Debug, Clone)]
pub struct PushBroker {
    pub(crate) options: BrokerGitOptions,
    pub(crate) git_timeout: Duration,
}

impl PushBroker {
    pub fn new(options: BrokerGitOptions) -> Self {
        Self {
            options,
            git_timeout: process::DEFAULT_GIT_TIMEOUT,
        }
    }

    /// Set the shared Git budget for each preview or execution operation.
    /// Human confirmation time is outside both budgets. This does not bound
    /// uninterruptible OS calls or physical snapshot copying.
    pub fn with_git_timeout(mut self, timeout: Duration) -> Result<Self, GitError> {
        if timeout.is_zero() || timeout > Duration::from_secs(3600) {
            return Err(GitError::UnsafeConfig {
                detail: "Git timeout must be positive and at most one hour".into(),
            });
        }
        self.git_timeout = timeout;
        Ok(self)
    }
}

impl Default for PushBroker {
    fn default() -> Self {
        Self::new(BrokerGitOptions::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_configuration_has_no_unlimited_or_overflowing_value() {
        assert_eq!(PushBroker::default().git_timeout, Duration::from_secs(300));
        for timeout in [Duration::ZERO, Duration::from_secs(3601), Duration::MAX] {
            assert!(PushBroker::default().with_git_timeout(timeout).is_err());
        }
        for timeout in [Duration::from_millis(50), Duration::from_secs(3600)] {
            assert!(PushBroker::default().with_git_timeout(timeout).is_ok());
        }
    }
}
