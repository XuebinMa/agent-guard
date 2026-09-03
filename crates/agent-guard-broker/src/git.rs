//! Running `git` as a subprocess, without a shell.
//!
//! Arguments are passed to the process directly, so a branch or remote name
//! containing shell metacharacters is data rather than syntax. Every call
//! names its repository explicitly instead of relying on the caller's working
//! directory.

use std::path::Path;
use std::process::Command;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GitError {
    #[error("git could not be run: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("git {command} failed: {stderr}")]
    Failed { command: String, stderr: String },
    #[error("git {command} produced output this did not expect: {detail}")]
    Unexpected { command: String, detail: String },
}

/// Run `git` in `repo` and return trimmed stdout, or the error git reported.
pub(crate) fn run(repo: &Path, args: &[&str]) -> Result<String, GitError> {
    let output = Command::new("git").args(args).current_dir(repo).output()?;

    if !output.status.success() {
        return Err(GitError::Failed {
            command: args.join(" "),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run `git` and report whether it exited zero, for the queries where a
/// non-zero exit is an answer rather than a failure.
pub(crate) fn succeeds(repo: &Path, args: &[&str]) -> Result<bool, GitError> {
    let output = Command::new("git").args(args).current_dir(repo).output()?;
    Ok(output.status.success())
}
