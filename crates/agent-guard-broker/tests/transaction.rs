//! What a push would actually do, resolved from the repository and the remote
//! rather than restated from the command line.
//!
//! `git push origin main` does not say which URL `origin` is, what the remote
//! currently holds, which commits would be added, or whether the update is a
//! fast-forward. A preview built from the command line shows the human the
//! same string the agent typed. A preview worth approving has to be resolved.
//!
//! These tests use a bare repository on disk as the remote, so they exercise
//! the real `git` plumbing without a network or a credential.

use std::path::{Path, PathBuf};
use std::process::Command;

use agent_guard_broker::{resolve_push_transaction, RefUpdateKind};

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

/// A working repo whose `origin` is a bare repo on disk, plus one commit
/// already shared with that remote.
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

    (dir, work, remote)
}

/// The resolved transaction names the remote URL, both object ids, and the
/// commits the remote does not yet have.
#[test]
fn resolves_the_commits_a_fast_forward_would_add() {
    let (_dir, work, remote) = repo_with_remote();
    let base = git(&work, &["rev-parse", "HEAD"]);
    let second = commit(&work, "second");
    let third = commit(&work, "third");

    let tx = resolve_push_transaction(&work, "origin", "main").expect("resolves");

    assert_eq!(tx.remote_url, remote.to_str().unwrap());
    assert_eq!(tx.local_oid, third);
    assert_eq!(tx.remote_oid.as_deref(), Some(base.as_str()));
    assert_eq!(tx.kind, RefUpdateKind::FastForward);
    assert_eq!(
        tx.added_commits,
        Some(vec![third.clone(), second.clone()]),
        "the preview must list what the remote does not have, newest first"
    );
}

/// A branch the remote does not have is a create, not an update, and has no
/// remote object id to compare against.
#[test]
fn resolves_a_new_branch_as_a_create() {
    let (_dir, work, _remote) = repo_with_remote();
    git(&work, &["checkout", "-b", "feature"]);
    let head = commit(&work, "on feature");

    let tx = resolve_push_transaction(&work, "origin", "feature").expect("resolves");

    assert_eq!(tx.kind, RefUpdateKind::Create);
    assert_eq!(tx.remote_oid, None);
    assert_eq!(tx.local_oid, head);
}

/// A history the remote cannot fast-forward to is the case a human most needs
/// to see before approving, so it is classified rather than left to the push
/// to discover.
#[test]
fn resolves_a_rewritten_history_as_not_fast_forward() {
    let (_dir, work, _remote) = repo_with_remote();
    commit(&work, "second");
    git(&work, &["push", "origin", "main"]);

    // Rewrite the shared commit: the remote tip is no longer an ancestor.
    git(&work, &["reset", "--hard", "HEAD~1"]);
    let rewritten = commit(&work, "different second");

    let tx = resolve_push_transaction(&work, "origin", "main").expect("resolves");

    assert_eq!(tx.kind, RefUpdateKind::NotFastForward);
    assert_eq!(tx.local_oid, rewritten);
    assert!(
        tx.remote_oid.is_some(),
        "a non-fast-forward must still name what it would overwrite"
    );
}

/// Nothing to do is its own answer. Approving a no-op push is a decision a
/// human should not be asked to make.
#[test]
fn resolves_an_already_pushed_branch_as_up_to_date() {
    let (_dir, work, _remote) = repo_with_remote();

    let tx = resolve_push_transaction(&work, "origin", "main").expect("resolves");

    assert_eq!(tx.kind, RefUpdateKind::UpToDate);
    assert_eq!(
        tx.added_commits,
        Some(Vec::new()),
        "nothing to add is an answer; it must not read as an unanswered question"
    );
}

/// A remote holding objects this repository never fetched cannot be
/// classified, and saying so is not the same as saying history would be
/// discarded.
///
/// This is a regression: the first implementation asked `merge-base
/// --is-ancestor` about an object it did not have, got a non-zero exit, and
/// reported `NotFastForward` — a confident answer that happened to be safe
/// for entirely the wrong reason. A human reading it would believe the tool
/// had established that commits would be lost.
#[test]
fn an_unfetched_remote_object_is_undetermined_not_not_fast_forward() {
    let (dir, work, remote) = repo_with_remote();

    // Another party advances the remote with a commit this repo never sees.
    let other = dir.path().join("other");
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

    commit(&work, "ours");
    let tx = resolve_push_transaction(&work, "origin", "main").expect("resolves");

    assert_eq!(
        tx.kind,
        RefUpdateKind::Undetermined,
        "an object we do not hold cannot be compared against"
    );
    assert_eq!(
        tx.added_commits, None,
        "an unanswerable question must not be reported as an empty answer"
    );
    assert!(
        tx.remote_oid.is_some(),
        "the remote tip is still known even when its history is not"
    );
}
