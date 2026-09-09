//! Executing exactly the approved push.
//!
//! ## The order is the security property
//!
//! Resolve once in a broker-owned Git snapshot, spend the grant against that
//! transaction, then push that same transaction from that same snapshot. The
//! source is the approved object id, the destination is the approved push URL,
//! and a lease pins the remote object the human saw.

use std::path::Path;

use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::git::{GitError, GitSnapshot, PushBroker};
use crate::grant::{grant_was_spent, peek_grant, spend_grant, GrantError, PushGrant};
use crate::receipt::{PushAttempt, PushReceipt, Witness};
use crate::transaction::{PushTransaction, RefUpdateKind};

/// What the broker did, and to what.
#[derive(Debug, Clone)]
pub struct PushOutcome {
    /// The object that was pushed. Named explicitly because the branch it
    /// went to may already point elsewhere locally.
    pub pushed_oid: String,
    pub branch: String,
    pub remote_url: String,
    /// The grant this push was authorized by, now spent.
    pub grant: PushGrant,
    /// What git reported, kept verbatim.
    pub git_output: String,
}

#[derive(Debug, Error)]
pub enum ExecuteError {
    #[error("could not resolve the transaction: {0}")]
    Resolve(#[source] GitError),
    /// The grant does not authorize what is now there. Kept distinct from a
    /// missing grant: this one says the world moved, which tells a human to
    /// look again rather than to find their approval.
    #[error("the approved transaction no longer describes this repository: {0}")]
    Drift(#[source] GrantError),
    #[error("no usable grant: {0}")]
    Unauthorized(#[source] GrantError),
    #[error("{kind:?} is not a shape the broker executes yet")]
    UnsupportedShape { kind: RefUpdateKind },
    #[error("git refused the push: {0}")]
    Push(#[source] GitError),
}

/// Compatibility wrapper using strict defaults: no inherited Git config and
/// no local-file remote.
pub fn execute_push(
    repo: &Path,
    grant_dir: &Path,
    grant_id: &str,
    policy_hash: &str,
    now: DateTime<Utc>,
) -> Result<PushOutcome, ExecuteError> {
    PushBroker::default().execute_push(repo, grant_dir, grant_id, policy_hash, now)
}

struct ExecutionAttempt {
    transaction: Option<PushTransaction>,
    grant_id: Option<String>,
    result: Result<PushOutcome, ExecuteError>,
}

impl PushBroker {
    /// Push exactly what `grant_id` authorized from an isolated snapshot.
    pub fn execute_push(
        &self,
        repo: &Path,
        grant_dir: &Path,
        grant_id: &str,
        policy_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<PushOutcome, ExecuteError> {
        self.execute_attempt(repo, grant_dir, grant_id, policy_hash, now)
            .result
    }

    fn execute_attempt(
        &self,
        repo: &Path,
        grant_dir: &Path,
        grant_id: &str,
        policy_hash: &str,
        now: DateTime<Utc>,
    ) -> ExecutionAttempt {
        // Advisory only. Spending below authenticates the target and consumes
        // the grant before any push is attempted.
        let target = match peek_grant(grant_dir, grant_id) {
            Ok(target) => target,
            Err(error) => {
                return ExecutionAttempt {
                    transaction: None,
                    grant_id: None,
                    result: Err(ExecuteError::Unauthorized(error)),
                }
            }
        };

        // Keep this snapshot alive through the push. There is one resolution,
        // so the transaction signed into the receipt is the one executed.
        let resolved = match self.resolve_with_snapshot(repo, &target.remote, &target.branch) {
            Ok(resolved) => resolved,
            Err(error) => {
                return ExecutionAttempt {
                    transaction: None,
                    grant_id: None,
                    result: Err(ExecuteError::Resolve(error)),
                }
            }
        };
        let current = resolved.transaction;

        let grant = match spend_grant(grant_dir, grant_id, &current, policy_hash, now) {
            Ok(grant) => grant,
            Err(error) => {
                let result = match error {
                    GrantError::TransactionMismatch { .. } => ExecuteError::Drift(error),
                    other => ExecuteError::Unauthorized(other),
                };
                return ExecutionAttempt {
                    transaction: Some(current),
                    grant_id: grant_was_spent(grant_dir, grant_id).then(|| grant_id.to_string()),
                    result: Err(result),
                };
            }
        };
        let consumed_grant_id = Some(grant.grant_id.clone());

        let result = if current.kind.is_executable() {
            push_pinned(&resolved.snapshot, &current)
                .map(|git_output| PushOutcome {
                    pushed_oid: current.local_oid.clone(),
                    branch: current.branch.clone(),
                    remote_url: current.remote_url.clone(),
                    grant,
                    git_output,
                })
                .map_err(ExecuteError::Push)
        } else {
            Err(ExecuteError::UnsupportedShape { kind: current.kind })
        };

        ExecutionAttempt {
            transaction: Some(current),
            grant_id: consumed_grant_id,
            result,
        }
    }
}

/// Run the push with both ends pinned from the broker-owned repository.
fn push_pinned(snapshot: &GitSnapshot, tx: &PushTransaction) -> Result<String, GitError> {
    let refspec = format!("{}:refs/heads/{}", tx.local_oid, tx.branch);

    match &tx.remote_oid {
        Some(remote_oid) => {
            let lease = format!("--force-with-lease=refs/heads/{}:{}", tx.branch, remote_oid);
            snapshot.push(&["push", "--no-verify", &lease, &tx.remote_url, &refspec])
        }
        None => {
            let lease = format!("--force-with-lease=refs/heads/{}:", tx.branch);
            snapshot.push(&["push", "--no-verify", &lease, &tx.remote_url, &refspec])
        }
    }
}

/// Compatibility wrapper using strict defaults.
pub fn execute_push_with_receipt(
    repo: &Path,
    grant_dir: &Path,
    grant_id: &str,
    policy_hash: &str,
    now: DateTime<Utc>,
    signing_key: Option<&ed25519_dalek::SigningKey>,
) -> PushReceipt {
    PushBroker::default().execute_push_with_receipt(
        repo,
        grant_dir,
        grant_id,
        policy_hash,
        now,
        signing_key,
    )
}

impl PushBroker {
    /// Execute once and seal the exact transaction and consumed grant into a
    /// receipt. A refusal before resolution legitimately has neither.
    pub fn execute_push_with_receipt(
        &self,
        repo: &Path,
        grant_dir: &Path,
        grant_id: &str,
        policy_hash: &str,
        now: DateTime<Utc>,
        signing_key: Option<&ed25519_dalek::SigningKey>,
    ) -> PushReceipt {
        let attempt = self.execute_attempt(repo, grant_dir, grant_id, policy_hash, now);
        let outcome = match attempt.result {
            Ok(_) => PushAttempt::Pushed,
            Err(error) => PushAttempt::Refused {
                reason: error.to_string(),
            },
        };

        PushReceipt {
            version: 1,
            at: now,
            transaction: attempt.transaction,
            grant_id: attempt.grant_id,
            attempt: outcome,
            witness: Witness::Unsigned,
        }
        .seal(signing_key)
    }
}
