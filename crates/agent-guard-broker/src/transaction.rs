//! Resolving what a push would actually do.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::git::{GitError, GitSnapshot, PushBroker};

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

impl RefUpdateKind {
    /// Whether the broker performs this shape today.
    ///
    /// `execute_push` is the enforcer; this is the same set asked as a
    /// question, so a caller can decline before spending a human's attention
    /// and a one-use grant on something that fails at execution. Both read
    /// this, because two copies of the set drift silently — the offer says
    /// yes, the execution says no, and by then the grant is gone.
    pub fn is_executable(self) -> bool {
        matches!(self, RefUpdateKind::FastForward | RefUpdateKind::Create)
    }
}

/// What an approval would be about: the effect, resolved, not the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushTransaction {
    /// The remote as named on the command line, e.g. `origin`.
    pub remote: String,
    /// The single push URL the broker will pass to both `ls-remote` and
    /// `push`. This is never replaced by the remote name during execution.
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
/// Every field is read at call time from an isolated, broker-owned Git
/// snapshot. A transaction is a snapshot of two
/// moving things — the local repository and the remote — and says nothing
/// about whether either still holds when a push eventually runs. Re-resolving
/// and comparing is how that is checked; this function does not do it.
pub fn resolve_push_transaction(
    repo: &Path,
    remote: &str,
    branch: &str,
) -> Result<PushTransaction, GitError> {
    PushBroker::default().resolve_push_transaction(repo, remote, branch)
}

impl PushBroker {
    pub fn resolve_push_transaction(
        &self,
        repo: &Path,
        remote: &str,
        branch: &str,
    ) -> Result<PushTransaction, GitError> {
        let snapshot = GitSnapshot::capture(repo, remote, branch, &self.options)?;
        resolve_from_snapshot(&snapshot, remote, branch)
    }
}

fn resolve_from_snapshot(
    snapshot: &GitSnapshot,
    remote: &str,
    branch: &str,
) -> Result<PushTransaction, GitError> {
    let remote_url = snapshot.remote_url.clone();
    resolve_from_snapshot_at_url(snapshot, remote, branch, &remote_url)
}

/// Resolve remote state only against an already-approved URL.
///
/// Execution calls this after atomically claiming a grant and proving the
/// repository-local URL and OID still match that grant. Keeping the URL an
/// explicit argument prevents an agent-controlled remote name from being
/// resolved again at the first network-capable command.
pub(crate) fn resolve_from_snapshot_at_url(
    snapshot: &GitSnapshot,
    remote: &str,
    branch: &str,
    approved_remote_url: &str,
) -> Result<PushTransaction, GitError> {
    let remote_url = approved_remote_url.to_string();
    let local_ref = format!("refs/heads/{branch}");
    let local_oid = snapshot.run(&["rev-parse", "--verify", &local_ref])?;

    let remote_oid = resolve_remote_oid(snapshot, &remote_url, branch)?;

    let (kind, added_commits) = match remote_oid.as_deref() {
        None => (
            RefUpdateKind::Create,
            Some(commits_between(snapshot, None, &local_oid)?),
        ),
        Some(remote_oid) if remote_oid == local_oid => (RefUpdateKind::UpToDate, Some(Vec::new())),
        // The remote is ahead by objects never fetched here. Neither
        // `merge-base` nor `rev-list` can say anything about an object this
        // repository does not have: the first would exit non-zero, which
        // reads identically to a genuine non-fast-forward, and the second
        // fails outright. Both questions are unanswerable, and saying so is
        // the only truthful option.
        Some(remote_oid) if !has_object(snapshot, remote_oid)? => {
            (RefUpdateKind::Undetermined, None)
        }
        Some(remote_oid) => {
            // `merge-base --is-ancestor` exits non-zero for "not an ancestor",
            // which is an answer rather than a failure.
            let fast_forward =
                snapshot.status_is(&["merge-base", "--is-ancestor", remote_oid, &local_oid], 1)?;
            let kind = if fast_forward {
                RefUpdateKind::FastForward
            } else {
                RefUpdateKind::NotFastForward
            };
            (
                kind,
                Some(commits_between(snapshot, Some(remote_oid), &local_oid)?),
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
fn resolve_remote_oid(
    snapshot: &GitSnapshot,
    remote_url: &str,
    branch: &str,
) -> Result<Option<String>, GitError> {
    let full_ref = format!("refs/heads/{branch}");
    // `--` keeps the URL and refspec positional even if a future value could be
    // read as an option. The ref argument is passed after it.
    let Some(listing) = snapshot.run_optional(
        &["ls-remote", "--exit-code", "--", remote_url, &full_ref],
        2,
    )?
    else {
        return Ok(None);
    };

    remote_tip_from_listing(&listing, &full_ref).map_err(|detail| GitError::Unexpected {
        command: format!("ls-remote {remote_url} {full_ref}"),
        detail,
    })
}

/// The object id an `ls-remote` listing reports for exactly `full_ref`.
fn remote_tip_from_listing(listing: &str, full_ref: &str) -> Result<Option<String>, String> {
    // `ls-remote` also matches on a `/`-boundary suffix, so another ref can
    // appear before the branch. Only an exact ref name describes the approved
    // branch's remote tip and the lease that will protect its update.
    for line in listing.lines() {
        let mut fields = line.split_whitespace();
        let oid = fields.next();
        let name = fields.next();
        if let (Some(oid), true) = (oid, name == Some(full_ref)) {
            // The remote wrote this value. It is printed in the preview and
            // passed to local rev resolution, where `HEAD` or a ref name would
            // resolve to something the remote never reported. The refusal
            // does not repeat it, for the same reason.
            if !is_object_id(oid) {
                return Err("the remote reported a tip that is not a Git object id".to_string());
            }
            return Ok(Some(oid.to_string()));
        }
    }

    // Any matches were only suffix matches of other refs, not this branch.
    Ok(None)
}

/// A full SHA-1 or SHA-256 object name, as `ls-remote` prints one.
fn is_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Whether this repository holds the object at all.
fn has_object(snapshot: &GitSnapshot, oid: &str) -> Result<bool, GitError> {
    snapshot.object_is_commit(oid)
}

/// The commits `to` has that `from` does not, newest first.
fn commits_between(
    snapshot: &GitSnapshot,
    from: Option<&str>,
    to: &str,
) -> Result<Vec<String>, GitError> {
    let range = match from {
        Some(from) => format!("{from}..{to}"),
        None => to.to_string(),
    };
    let listing = snapshot.run(&["rev-list", &range])?;
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
    PushBroker::default().drift_against(approved, repo)
}

impl PushBroker {
    pub fn drift_against(
        &self,
        approved: &PushTransaction,
        repo: &Path,
    ) -> Result<Vec<Drift>, GitError> {
        let current = self.resolve_push_transaction(repo, &approved.remote, &approved.branch)?;
        Ok(current.drift_from(approved))
    }
}

#[cfg(test)]
mod tests {
    use super::remote_tip_from_listing;

    const OID: &str = "0123456789abcdef0123456789abcdef01234567";

    /// The remote chooses what `ls-remote` prints. Its tip is shown to the
    /// approver and handed to `merge-base`, `rev-list` and the push lease, so
    /// anything but a full object id is refused rather than shown or resolved.
    #[test]
    fn a_remote_tip_that_is_not_an_object_id_is_refused() {
        for tip in [
            "HEAD",
            "main",
            "0123456",
            "\u{1b}[2K0123456789abcdef0123456789abcdef01234567",
            "0123456789abcdef0123456789abcdef0123456g",
            "0123456789abcdef0123456789abcdef012345678",
        ] {
            let listing = format!("{tip}\trefs/heads/main\n");
            let error = remote_tip_from_listing(&listing, "refs/heads/main")
                .expect_err("a tip that is not an object id must be refused");
            assert!(
                !error.chars().any(char::is_control),
                "the refusal must not repeat the remote's bytes: {error:?}"
            );
        }
    }

    #[test]
    fn a_full_object_id_for_the_exact_ref_is_returned() {
        let sha256 = "a".repeat(64);
        for oid in [OID, sha256.as_str()] {
            let listing = format!("{oid}\trefs/heads/feature/main\n{oid}\trefs/heads/main\n");
            assert_eq!(
                remote_tip_from_listing(&listing, "refs/heads/main"),
                Ok(Some(oid.to_string()))
            );
        }
        let decoy = format!("{OID}\trefs/heads/feature/main\n");
        assert_eq!(remote_tip_from_listing(&decoy, "refs/heads/main"), Ok(None));
    }
}
