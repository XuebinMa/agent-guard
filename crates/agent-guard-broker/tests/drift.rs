//! An approval is about a snapshot. A push happens later, against a reality
//! that may have moved.
//!
//! Both sides move on their own: the agent can commit again, and the remote
//! can be advanced by anyone else. Approving one transaction and executing a
//! different one is the failure this guards against, and it is the reason an
//! approved transaction is re-resolved immediately before the push rather
//! than trusted.

use std::path::{Path, PathBuf};
use std::process::Command;

use agent_guard_broker::{drift_against, resolve_push_transaction, Drift};

fn git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn commit(repo: &Path, message: &str) -> String {
    std::fs::write(repo.join("file.txt"), message).expect("write");
    git(repo, &["add", "."]);
    git(repo, &["commit", "-m", message]);
    git(repo, &["rev-parse", "HEAD"])
}

fn repo_with_remote() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let remote = dir.path().join("remote.git");
    let work = dir.path().join("work");
    std::fs::create_dir_all(&work).expect("mkdir");

    Command::new("git")
        .args(["init", "--bare", "-b", "main"])
        .arg(&remote)
        .output()
        .expect("git init --bare");

    git(&work, &["init", "-b", "main"]);
    git(&work, &["config", "user.email", "test@example.invalid"]);
    git(&work, &["config", "user.name", "Test"]);
    git(
        &work,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    commit(&work, "first");
    git(&work, &["push", "origin", "main"]);
    commit(&work, "second");

    (dir, work, remote)
}

/// Nothing moved: the approval still describes what would happen.
#[test]
fn an_unchanged_repository_reports_no_drift() {
    let (_dir, work, _remote) = repo_with_remote();
    let approved = resolve_push_transaction(&work, "origin", "main").expect("resolves");

    let drift = drift_against(&approved, &work).expect("re-resolves");

    assert!(drift.is_empty(), "unexpected drift: {drift:?}");
}

/// The agent committed again after the human approved. The push would now
/// carry a commit nobody looked at.
#[test]
fn a_further_local_commit_is_drift() {
    let (_dir, work, _remote) = repo_with_remote();
    let approved = resolve_push_transaction(&work, "origin", "main").expect("resolves");

    let sneaked = commit(&work, "added after approval");

    let drift = drift_against(&approved, &work).expect("re-resolves");

    assert!(
        drift.contains(&Drift::LocalMoved),
        "a new local commit must be drift: {drift:?}"
    );
    let current = resolve_push_transaction(&work, "origin", "main").expect("resolves");
    assert_eq!(current.local_oid, sneaked);
}

/// Someone else pushed in the meantime. The approved update would now be
/// applied on top of a different remote state, or would discard it.
#[test]
fn a_remote_advanced_by_someone_else_is_drift() {
    let (_dir, work, remote) = repo_with_remote();
    let approved = resolve_push_transaction(&work, "origin", "main").expect("resolves");

    // A second clone stands in for the other party.
    let other = _dir.path().join("other");
    Command::new("git")
        .args(["clone"])
        .arg(&remote)
        .arg(&other)
        .output()
        .expect("clone");
    git(&other, &["config", "user.email", "other@example.invalid"]);
    git(&other, &["config", "user.name", "Other"]);
    commit(&other, "theirs");
    git(&other, &["push", "origin", "main"]);

    let drift = drift_against(&approved, &work).expect("re-resolves");

    assert!(
        drift.contains(&Drift::RemoteMoved),
        "a remote advanced by another party must be drift: {drift:?}"
    );
}

/// The remote name still says `origin`. Where it points does not have to.
#[test]
fn a_repointed_remote_is_drift() {
    let (_dir, work, _remote) = repo_with_remote();
    let approved = resolve_push_transaction(&work, "origin", "main").expect("resolves");

    let elsewhere = _dir.path().join("elsewhere.git");
    Command::new("git")
        .args(["init", "--bare", "-b", "main"])
        .arg(&elsewhere)
        .output()
        .expect("git init --bare");
    git(
        &work,
        &["remote", "set-url", "origin", elsewhere.to_str().unwrap()],
    );

    let drift = drift_against(&approved, &work).expect("re-resolves");

    assert!(
        drift.contains(&Drift::RemoteUrlChanged),
        "the same remote name pointing somewhere else must be drift: {drift:?}"
    );
}

/// The subtle one. Both sides can move so that the classification is
/// unchanged — still a fast-forward — while the effect is entirely different.
/// A check that compares only the kind passes this.
#[test]
fn drift_is_detected_even_when_the_update_kind_is_unchanged() {
    let (_dir, work, _remote) = repo_with_remote();
    let approved = resolve_push_transaction(&work, "origin", "main").expect("resolves");
    assert_eq!(
        approved.kind,
        agent_guard_broker::RefUpdateKind::FastForward
    );

    commit(&work, "third");

    let current = resolve_push_transaction(&work, "origin", "main").expect("resolves");
    assert_eq!(current.kind, approved.kind, "the kind is unchanged");
    assert_ne!(
        current.digest(),
        approved.digest(),
        "but the effect is not, and the digest must say so"
    );

    let drift = drift_against(&approved, &work).expect("re-resolves");
    assert!(!drift.is_empty());
}
