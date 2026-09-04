//! Executing exactly the approved push.
//!
//! ## The order is the security property
//!
//! Resolve first, then spend the grant against what was just resolved, then
//! push. Spending against a freshly resolved transaction makes authorization
//! and drift detection the same check: a grant is bound to a digest, so a
//! transaction that moved no longer matches the grant and cannot be spent.
//! There is no separate "did it drift?" step to forget to call.
//!
//! ## Both ends are pinned in the push itself
//!
//! A gap remains between resolving and pushing, and neither end stops moving
//! during it, so the push is written so that git enforces the approval rather
//! than trusting a reading taken moments earlier:
//!
//! - the **source** is the approved object id, not the branch name. Pushing
//!   `main` would send whatever `main` points at when git runs, which is not
//!   necessarily what the human saw.
//! - the **destination** carries a lease on the remote object id that was
//!   approved, so the server refuses if the remote is no longer what the
//!   human was shown. A remote advanced by someone else is a state nobody
//!   approved, even when the update would still fast-forward.
//!
//! ## What this does not establish
//!
//! Credential isolation is a deployment property this code cannot verify.
//! The push inherits this process's environment, so it uses whatever
//! credential the broker has. That is only a boundary if the agent has none
//! of its own; nothing here can check that, and nothing here prevents an
//! agent holding a credential from pushing without a grant.

use std::path::Path;

use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::git::{run, GitError};
use crate::grant::{peek_grant, spend_grant, GrantError, PushGrant};
use crate::receipt::{PushAttempt, PushReceipt, Witness};
use crate::transaction::{resolve_push_transaction, PushTransaction, RefUpdateKind};

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

/// Push exactly what `grant_id` authorized, or refuse.
pub fn execute_push(
    repo: &Path,
    grant_dir: &Path,
    grant_id: &str,
    policy_hash: &str,
    now: DateTime<Utc>,
) -> Result<PushOutcome, ExecuteError> {
    // Advisory read: it only decides what to resolve. The spend below is
    // what authenticates, and it compares a digest covering every field that
    // defines the effect.
    let target = peek_grant(grant_dir, grant_id).map_err(ExecuteError::Unauthorized)?;

    let current = resolve_push_transaction(repo, &target.remote, &target.branch)
        .map_err(ExecuteError::Resolve)?;

    // Spending against the freshly resolved transaction is the drift check.
    let grant =
        spend_grant(grant_dir, grant_id, &current, policy_hash, now).map_err(
            |error| match error {
                GrantError::TransactionMismatch { .. } => ExecuteError::Drift(error),
                other => ExecuteError::Unauthorized(other),
            },
        )?;

    // Only the shapes the first supported slice covers. Anything that would
    // discard history fails closed rather than being forced through, and the
    // grant is already spent, so a refusal here costs a fresh approval.
    match current.kind {
        RefUpdateKind::FastForward | RefUpdateKind::Create => {}
        kind => return Err(ExecuteError::UnsupportedShape { kind }),
    }

    let git_output = push_pinned(repo, &current).map_err(ExecuteError::Push)?;

    Ok(PushOutcome {
        pushed_oid: current.local_oid,
        branch: current.branch,
        remote_url: current.remote_url,
        grant,
        git_output,
    })
}

/// Run the push with both ends pinned.
fn push_pinned(repo: &Path, tx: &PushTransaction) -> Result<String, GitError> {
    let refspec = format!("{}:refs/heads/{}", tx.local_oid, tx.branch);

    match &tx.remote_oid {
        // Updating a branch: require the remote to still be the object the
        // human was shown. The lease is a precondition, not permission to
        // force; a non-fast-forward was already refused above.
        Some(remote_oid) => {
            let lease = format!("--force-with-lease=refs/heads/{}:{}", tx.branch, remote_oid);
            run(repo, &["push", &lease, &tx.remote, &refspec])
        }
        // Creating a branch: require that it still does not exist.
        None => {
            let lease = format!("--force-with-lease=refs/heads/{}:", tx.branch);
            run(repo, &["push", &lease, &tx.remote, &refspec])
        }
    }
}

/// Execute, and record what happened either way.
///
/// This is the entry point a broker should use. [`execute_push`] returns a
/// `Result` and leaves the caller to decide whether a refusal is worth
/// recording; this one records both, because a broker that only writes down
/// its successes cannot show that it ever declined.
pub fn execute_push_with_receipt(
    repo: &Path,
    grant_dir: &Path,
    grant_id: &str,
    policy_hash: &str,
    now: DateTime<Utc>,
    signing_key: Option<&ed25519_dalek::SigningKey>,
) -> PushReceipt {
    // Resolved separately from the attempt so a refusal can still describe
    // what it refused. A failure here leaves the receipt without a
    // transaction, which is the truthful shape for an attempt that never got
    // far enough to have an effect.
    let transaction = peek_grant(grant_dir, grant_id)
        .ok()
        .and_then(|target| resolve_push_transaction(repo, &target.remote, &target.branch).ok());

    let (attempt, grant_id_used) = match execute_push(repo, grant_dir, grant_id, policy_hash, now) {
        Ok(outcome) => (PushAttempt::Pushed, Some(outcome.grant.grant_id)),
        Err(error) => (
            PushAttempt::Refused {
                reason: error.to_string(),
            },
            None,
        ),
    };

    PushReceipt {
        version: 1,
        at: now,
        transaction,
        grant_id: grant_id_used,
        attempt,
        witness: Witness::Unsigned,
    }
    .seal(signing_key)
}
