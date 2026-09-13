//! The broker's isolated Git execution context.
//!
//! The repository belongs to the agent. Its config, hooks and object-store
//! indirections are therefore input, never execution context. Every operation
//! that can contact a remote runs from a broker-owned temporary bare
//! repository containing a regular-file snapshot of the source refs and
//! primary object database.

mod command;
mod snapshot;
mod validate;

use std::path::PathBuf;

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
#[derive(Debug, Clone, Default)]
pub struct PushBroker {
    pub(crate) options: BrokerGitOptions,
}

impl PushBroker {
    pub fn new(options: BrokerGitOptions) -> Self {
        Self { options }
    }
}
