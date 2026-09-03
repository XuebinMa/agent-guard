//! Resolving what a push would actually do.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::git::{run, succeeds, GitError};

/// How the remote reference would change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefUpdateKind {
    /// The remote does not have this reference yet.
    Create,
    /// The remote's tip is an ancestor of the local tip: nothing is discarded.
    FastForward,
    /// The remote's tip is not an ancestor. Applying this discards commits the
    /// remote has, which is the case a human most needs to see before
    /// approving, so it is classified here rather than left for the push to
    /// discover.
    NotFastForward,
    /// The remote already holds exactly this. Approving a no-op is a decision
    /// nobody should be asked to make.
    UpToDate,
    /// The remote holds an object this repository does not have, so the
    /// relationship between the two tips cannot be established without
    /// fetching.
    ///
    /// This is its own state rather than a pessimistic `NotFastForward`.
    /// Reporting "this would discard history" when the truth is "this cannot
    /// be determined" tells a human something was established that was not,
    /// and the two call for different actions: one is a decision to make, the
    /// other is a fetch to run first.
    Undetermined,
}

/// What an approval would be about: the effect, resolved, not the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushTransaction {
    /// The remote as named on the command line, e.g. `origin`.
    pub remote: String,
    /// What that name resolves to. A remote can be renamed or repointed
    /// between an approval and a push, so the URL is part of the transaction
    /// rather than a detail of the repository.
    pub remote_url: String,
    /// The branch being pushed, without `refs/heads/`.
    pub branch: String,
    /// The object the local branch points at.
    pub local_oid: String,
    /// The object the remote branch points at, or `None` when creating it.
    pub remote_oid: Option<String>,
    pub kind: RefUpdateKind,
    /// Commits the remote does not have, newest first.
    ///
    /// `Some(vec![])` means the answer is none. `None` means the question
    /// could not be answered — the remote holds objects this repository does
    /// not have — and must not be shown to a human as an empty list, which
    /// reads as "this push adds nothing".
    pub added_commits: Option<Vec<String>>,
}

/// Resolve the transaction a push of `branch` to `remote` would perform.
///
/// Every field is read at call time. A transaction is a snapshot of two
/// moving things — the local repository and the remote — and says nothing
/// about whether either still holds when a push eventually runs. Re-resolving
/// and comparing is how that is checked; this function does not do it.
pub fn resolve_push_transaction(
    repo: &Path,
    remote: &str,
    branch: &str,
) -> Result<PushTransaction, GitError> {
    let remote_url = run(repo, &["remote", "get-url", remote])?;
    let local_ref = format!("refs/heads/{branch}");
    let local_oid = run(repo, &["rev-parse", "--verify", &local_ref])?;

    let remote_oid = resolve_remote_oid(repo, remote, branch)?;

    let (kind, added_commits) = match remote_oid.as_deref() {
        None => (
            RefUpdateKind::Create,
            Some(commits_between(repo, None, &local_oid)?),
        ),
        Some(remote_oid) if remote_oid == local_oid => (RefUpdateKind::UpToDate, Some(Vec::new())),
        // The remote is ahead by objects never fetched here. Neither
        // `merge-base` nor `rev-list` can say anything about an object this
        // repository does not have: the first would exit non-zero, which
        // reads identically to a genuine non-fast-forward, and the second
        // fails outright. Both questions are unanswerable, and saying so is
        // the only truthful option.
        Some(remote_oid) if !has_object(repo, remote_oid)? => (RefUpdateKind::Undetermined, None),
        Some(remote_oid) => {
            // `merge-base --is-ancestor` exits non-zero for "not an ancestor",
            // which is an answer rather than a failure.
            let fast_forward = succeeds(
                repo,
                &["merge-base", "--is-ancestor", remote_oid, &local_oid],
            )?;
            let kind = if fast_forward {
                RefUpdateKind::FastForward
            } else {
                RefUpdateKind::NotFastForward
            };
            (
                kind,
                Some(commits_between(repo, Some(remote_oid), &local_oid)?),
            )
        }
    };

    Ok(PushTransaction {
        remote: remote.to_string(),
        remote_url,
        branch: branch.to_string(),
        local_oid,
        remote_oid,
        kind,
        added_commits,
    })
}

/// Ask the remote what it holds for `branch`.
///
/// This queries the remote itself rather than reading the local
/// remote-tracking ref, which is a cached answer that may be arbitrarily
/// stale and is exactly what a preview must not be built on.
fn resolve_remote_oid(repo: &Path, remote: &str, branch: &str) -> Result<Option<String>, GitError> {
    let refspec = format!("refs/heads/{branch}");
    let output = run(repo, &["ls-remote", "--exit-code", remote, &refspec]);

    let listing = match output {
        Ok(listing) => listing,
        // `--exit-code` reports "no matching ref" as a failure; for a branch
        // the remote simply does not have yet, that is the answer.
        Err(GitError::Failed { .. }) => return Ok(None),
        Err(other) => return Err(other),
    };

    if listing.is_empty() {
        return Ok(None);
    }

    let oid = listing
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().next())
        .ok_or_else(|| GitError::Unexpected {
            command: format!("ls-remote {remote} {refspec}"),
            detail: listing.clone(),
        })?;

    Ok(Some(oid.to_string()))
}

/// Whether this repository holds the object at all.
fn has_object(repo: &Path, oid: &str) -> Result<bool, GitError> {
    succeeds(repo, &["cat-file", "-e", &format!("{oid}^{{commit}}")])
}

/// The commits `to` has that `from` does not, newest first.
fn commits_between(repo: &Path, from: Option<&str>, to: &str) -> Result<Vec<String>, GitError> {
    let range = match from {
        Some(from) => format!("{from}..{to}"),
        None => to.to_string(),
    };
    let listing = run(repo, &["rev-list", &range])?;
    Ok(listing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

/// One way a re-resolved transaction differs from the approved one.
///
/// Named individually rather than reported as a single "changed" because the
/// situations call for different answers from a human: a remote someone else
/// advanced is a merge to do, an agent that committed again is a new approval
/// to seek, and a remote that now points elsewhere is a question about the
/// repository itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Drift {
    /// The name resolves to a different URL than it did at approval.
    RemoteUrlChanged,
    /// The local branch is no longer the object that was approved.
    LocalMoved,
    /// The remote branch is no longer the object that was approved.
    RemoteMoved,
    /// The update changed category, e.g. a fast-forward became one that would
    /// discard history.
    KindChanged,
    /// The set of commits the push would add is not the approved set.
    CommitsChanged,
}

impl PushTransaction {
    /// A stable digest of everything that defines the effect.
    ///
    /// The fields are restated into the preimage explicitly rather than
    /// serialized as a struct, so what the digest covers is readable here and
    /// adding a field cannot silently widen it.
    pub fn digest(&self) -> String {
        use sha2::{Digest, Sha256};

        let preimage = serde_json::to_vec(&(
            "agent-guard/push-transaction/v1",
            &self.remote,
            &self.remote_url,
            &self.branch,
            &self.local_oid,
            &self.remote_oid,
            &self.kind,
            &self.added_commits,
        ))
        .expect("push transaction digest preimage should always serialize");

        hex::encode(Sha256::digest(preimage))
    }

    /// Every way `self` differs from `approved`, empty when they describe the
    /// same effect.
    pub fn drift_from(&self, approved: &PushTransaction) -> Vec<Drift> {
        let mut drift = Vec::new();
        if self.remote_url != approved.remote_url {
            drift.push(Drift::RemoteUrlChanged);
        }
        if self.local_oid != approved.local_oid {
            drift.push(Drift::LocalMoved);
        }
        if self.remote_oid != approved.remote_oid {
            drift.push(Drift::RemoteMoved);
        }
        if self.kind != approved.kind {
            drift.push(Drift::KindChanged);
        }
        if self.added_commits != approved.added_commits {
            drift.push(Drift::CommitsChanged);
        }
        drift
    }
}

/// Re-resolve the approved transaction against the repository as it is now,
/// and report every difference.
///
/// This is the check that has to run immediately before a push rather than at
/// approval time. Its value is entirely in when it runs: an approval describes
/// a snapshot of two independently moving things, and the gap between deciding
/// and acting is where they move.
///
/// A resolution failure is not drift. It is returned as an error, because
/// "the repository no longer answers" is not the same as "the effect changed"
/// and must not be reported as an approved push being safe.
pub fn drift_against(approved: &PushTransaction, repo: &Path) -> Result<Vec<Drift>, GitError> {
    let current = resolve_push_transaction(repo, &approved.remote, &approved.branch)?;
    Ok(current.drift_from(approved))
}
