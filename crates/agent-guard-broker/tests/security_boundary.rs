//! Adversarial tests for the credential-bearing Git boundary.

use std::path::{Path, PathBuf};
use std::process::Command;

use agent_guard_broker::{issue_grant, BrokerGitOptions, ExecuteError, PushAttempt, PushBroker};
use chrono::{Duration, Utc};

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

struct Fixture {
    _dir: tempfile::TempDir,
    work: PathBuf,
    fetch_remote: PathBuf,
    grants: PathBuf,
    trusted_config: PathBuf,
}

impl Fixture {
    fn broker(&self) -> PushBroker {
        PushBroker::new(BrokerGitOptions {
            trusted_config: Some(self.trusted_config.clone()),
            allow_local_file_remote: true,
        })
    }
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let fetch_remote = dir.path().join("fetch.git");
    let work = dir.path().join("work");
    let grants = dir.path().join("grants");
    let trusted_config = dir.path().join("broker.gitconfig");
    std::fs::create_dir_all(&work).expect("mkdir");
    std::fs::write(&trusted_config, b"").expect("trusted config");

    Command::new("git")
        .args(["init", "--bare", "-b", "main"])
        .arg(&fetch_remote)
        .output()
        .expect("git init --bare");
    git(&work, &["init", "-b", "main"]);
    git(&work, &["config", "user.email", "test@example.invalid"]);
    git(&work, &["config", "user.name", "Test"]);
    git(
        &work,
        &["remote", "add", "origin", fetch_remote.to_str().unwrap()],
    );
    commit(&work, "first");
    git(&work, &["push", "origin", "main"]);

    Fixture {
        _dir: dir,
        work,
        fetch_remote,
        grants,
        trusted_config,
    }
}

#[test]
fn approved_push_url_is_the_only_remote_updated_and_receipted() {
    let f = fixture();
    let push_remote = f.work.parent().unwrap().join("push.git");
    Command::new("git")
        .args(["clone", "--bare"])
        .arg(&f.fetch_remote)
        .arg(&push_remote)
        .output()
        .expect("clone bare");
    git(
        &f.work,
        &[
            "remote",
            "set-url",
            "--push",
            "origin",
            push_remote.to_str().unwrap(),
        ],
    );
    let fetch_before = git(&f.fetch_remote, &["rev-parse", "refs/heads/main"]);
    let pushed = commit(&f.work, "second");
    let broker = f.broker();
    let tx = broker
        .resolve_push_transaction(&f.work, "origin", "main")
        .expect("resolve push URL");
    assert_eq!(tx.remote_url, push_remote.to_str().unwrap());
    let grant =
        issue_grant(&f.grants, &tx, "policy-1", "human", Duration::minutes(5)).expect("grant");

    let receipt =
        broker.execute_push_with_receipt(&f.work, &f.grants, &grant, "policy-1", Utc::now(), None);

    assert_eq!(receipt.attempt, PushAttempt::Pushed);
    assert_eq!(
        receipt.transaction.as_ref().unwrap().remote_url,
        push_remote.to_str().unwrap()
    );
    assert_eq!(
        git(&f.fetch_remote, &["rev-parse", "refs/heads/main"]),
        fetch_before,
        "the fetch URL must not receive the push"
    );
    assert_eq!(
        git(&push_remote, &["rev-parse", "refs/heads/main"]),
        pushed,
        "the exact approved push URL receives the object"
    );
}

#[test]
fn changing_the_push_url_after_approval_cannot_redirect_execution() {
    let f = fixture();
    let other_remote = f.work.parent().unwrap().join("other.git");
    Command::new("git")
        .args(["clone", "--bare"])
        .arg(&f.fetch_remote)
        .arg(&other_remote)
        .output()
        .expect("clone bare");
    let original_tip = git(&f.fetch_remote, &["rev-parse", "refs/heads/main"]);
    commit(&f.work, "second");
    let broker = f.broker();
    let approved = broker
        .resolve_push_transaction(&f.work, "origin", "main")
        .expect("resolve");
    let grant = issue_grant(
        &f.grants,
        &approved,
        "policy-1",
        "human",
        Duration::minutes(5),
    )
    .expect("grant");

    git(
        &f.work,
        &[
            "remote",
            "set-url",
            "--push",
            "origin",
            other_remote.to_str().unwrap(),
        ],
    );
    let result = broker.execute_push(&f.work, &f.grants, &grant, "policy-1", Utc::now());

    assert!(matches!(result, Err(ExecuteError::Drift(_))), "{result:?}");
    assert_eq!(
        git(&f.fetch_remote, &["rev-parse", "refs/heads/main"]),
        original_tip
    );
    assert_eq!(
        git(&other_remote, &["rev-parse", "refs/heads/main"]),
        original_tip
    );
}

#[cfg(unix)]
#[test]
fn repository_hooks_and_execution_config_are_not_loaded() {
    use std::os::unix::fs::PermissionsExt;

    let f = fixture();
    let outside = f.work.parent().unwrap();
    let hook_marker = outside.join("hook-marker");
    let receive_marker = outside.join("receive-marker");
    let hooks = outside.join("agent-hooks");
    std::fs::create_dir_all(&hooks).expect("hooks");
    let hook = hooks.join("pre-push");
    std::fs::write(
        &hook,
        format!("#!/bin/sh\ntouch '{}'\n", hook_marker.display()),
    )
    .expect("hook");
    let mut mode = std::fs::metadata(&hook).unwrap().permissions();
    mode.set_mode(0o755);
    std::fs::set_permissions(&hook, mode).unwrap();
    let receive = outside.join("receive-pack");
    std::fs::write(
        &receive,
        format!("#!/bin/sh\ntouch '{}'\nexit 1\n", receive_marker.display()),
    )
    .expect("receive pack");
    let mut mode = std::fs::metadata(&receive).unwrap().permissions();
    mode.set_mode(0o755);
    std::fs::set_permissions(&receive, mode).unwrap();

    git(
        &f.work,
        &["config", "core.hooksPath", hooks.to_str().unwrap()],
    );
    git(
        &f.work,
        &[
            "config",
            "remote.origin.receivepack",
            receive.to_str().unwrap(),
        ],
    );
    commit(&f.work, "second");
    let broker = f.broker();
    let tx = broker
        .resolve_push_transaction(&f.work, "origin", "main")
        .expect("resolve");
    let grant =
        issue_grant(&f.grants, &tx, "policy-1", "human", Duration::minutes(5)).expect("grant");

    broker
        .execute_push(&f.work, &f.grants, &grant, "policy-1", Utc::now())
        .expect("isolated push");

    assert!(!hook_marker.exists(), "repository hooks must not execute");
    assert!(
        !receive_marker.exists(),
        "repository receive-pack config must not execute"
    );
}

#[cfg(unix)]
#[test]
fn a_git_refusal_keeps_the_spent_grant_without_running_the_source_hook() {
    use std::os::unix::fs::PermissionsExt;

    let f = fixture();
    let source_marker = f.work.parent().unwrap().join("failed-push-source-hook");
    let source_hook = f.work.join(".git/hooks/pre-push");
    std::fs::write(
        &source_hook,
        format!("#!/bin/sh\ntouch '{}'\n", source_marker.display()),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&source_hook).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&source_hook, permissions).unwrap();

    let remote_hook = f.fetch_remote.join("hooks/pre-receive");
    std::fs::write(&remote_hook, b"#!/bin/sh\nexit 1\n").unwrap();
    let mut permissions = std::fs::metadata(&remote_hook).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&remote_hook, permissions).unwrap();

    commit(&f.work, "second");
    let broker = f.broker();
    let tx = broker
        .resolve_push_transaction(&f.work, "origin", "main")
        .expect("resolve");
    let grant =
        issue_grant(&f.grants, &tx, "policy-1", "human", Duration::minutes(5)).expect("grant");

    let receipt =
        broker.execute_push_with_receipt(&f.work, &f.grants, &grant, "policy-1", Utc::now(), None);

    assert!(matches!(receipt.attempt, PushAttempt::Refused { .. }));
    assert_eq!(receipt.grant_id.as_deref(), Some(grant.as_str()));
    assert!(
        !source_marker.exists(),
        "a source hook must not run even when Git later refuses the push"
    );
}

#[test]
fn repository_url_rewrites_do_not_change_the_approved_destination() {
    let f = fixture();
    let rewritten = f.work.parent().unwrap().join("rewritten.git");
    Command::new("git")
        .args(["clone", "--bare"])
        .arg(&f.fetch_remote)
        .arg(&rewritten)
        .output()
        .expect("clone bare");
    let key = format!("url.{}.pushInsteadOf", rewritten.display());
    git(&f.work, &["config", &key, f.fetch_remote.to_str().unwrap()]);
    let rewritten_before = git(&rewritten, &["rev-parse", "refs/heads/main"]);
    let pushed = commit(&f.work, "second");
    let broker = f.broker();
    let tx = broker
        .resolve_push_transaction(&f.work, "origin", "main")
        .expect("resolve");
    assert_eq!(tx.remote_url, f.fetch_remote.to_str().unwrap());
    let grant =
        issue_grant(&f.grants, &tx, "policy-1", "human", Duration::minutes(5)).expect("grant");
    broker
        .execute_push(&f.work, &f.grants, &grant, "policy-1", Utc::now())
        .expect("push");

    assert_eq!(
        git(&f.fetch_remote, &["rev-parse", "refs/heads/main"]),
        pushed
    );
    assert_eq!(
        git(&rewritten, &["rev-parse", "refs/heads/main"]),
        rewritten_before
    );
}

#[test]
fn trusted_config_is_narrow_and_must_live_outside_the_repository() {
    let f = fixture();
    let inside = f.work.join("broker.gitconfig");
    std::fs::write(&inside, b"[credential]\n\thelper = cache\n").unwrap();
    let inside_broker = PushBroker::new(BrokerGitOptions {
        trusted_config: Some(inside),
        allow_local_file_remote: true,
    });
    assert!(inside_broker
        .resolve_push_transaction(&f.work, "origin", "main")
        .is_err());

    for forbidden in [
        b"[core]\n\tsshCommand = touch /tmp/should-not-run\n".as_slice(),
        b"[include]\n\tpath = /tmp/agent-controlled.gitconfig\n".as_slice(),
        b"[url \"ssh://elsewhere/\"]\n\tinsteadOf = https://approved/\n".as_slice(),
        b"[protocol \"ext\"]\n\tallow = always\n".as_slice(),
    ] {
        std::fs::write(&f.trusted_config, forbidden).unwrap();
        assert!(
            f.broker()
                .resolve_push_transaction(&f.work, "origin", "main")
                .is_err(),
            "execution-bearing and destination-rewriting keys must be rejected"
        );
    }
}

#[cfg(unix)]
#[test]
fn trusted_config_rejects_symlinks_and_group_writable_files() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let f = fixture();
    let symlinked = f.work.parent().unwrap().join("linked.gitconfig");
    symlink(&f.trusted_config, &symlinked).unwrap();
    let linked_broker = PushBroker::new(BrokerGitOptions {
        trusted_config: Some(symlinked),
        allow_local_file_remote: true,
    });
    assert!(linked_broker
        .resolve_push_transaction(&f.work, "origin", "main")
        .is_err());

    let mut permissions = std::fs::metadata(&f.trusted_config).unwrap().permissions();
    permissions.set_mode(0o620);
    std::fs::set_permissions(&f.trusted_config, permissions).unwrap();
    assert!(f
        .broker()
        .resolve_push_transaction(&f.work, "origin", "main")
        .is_err());
}

#[cfg(unix)]
#[test]
fn repository_data_symlinks_fail_closed() {
    use std::os::unix::fs::symlink;

    let f = fixture();
    let objects = f.work.join(".git/objects");
    let loose_dir = (0_u8..=u8::MAX)
        .map(|value| objects.join(format!("{value:02x}")))
        .find(|path| !path.exists())
        .expect("an unused loose-object directory");
    std::fs::create_dir(&loose_dir).unwrap();
    symlink(
        f.work.join(".git/config"),
        loose_dir.join("11111111111111111111111111111111111111"),
    )
    .unwrap();

    assert!(f
        .broker()
        .resolve_push_transaction(&f.work, "origin", "main")
        .is_err());
}

#[test]
fn object_alternates_and_missing_remotes_fail_closed() {
    let f = fixture();
    let info = f.work.join(".git/objects/info");
    std::fs::create_dir_all(&info).unwrap();
    std::fs::write(info.join("alternates"), "/tmp/other-objects\n").unwrap();
    assert!(f
        .broker()
        .resolve_push_transaction(&f.work, "origin", "main")
        .is_err());

    std::fs::remove_file(info.join("alternates")).unwrap();
    git(
        &f.work,
        &[
            "remote",
            "set-url",
            "origin",
            f.work
                .parent()
                .unwrap()
                .join("missing.git")
                .to_str()
                .unwrap(),
        ],
    );
    assert!(
        f.broker()
            .resolve_push_transaction(&f.work, "origin", "main")
            .is_err(),
        "transport failure is not an absent branch"
    );
}

#[test]
fn partial_clone_and_promisor_repositories_fail_closed() {
    let partial = fixture();
    git(
        &partial.work,
        &["config", "extensions.partialClone", "origin"],
    );
    assert!(partial
        .broker()
        .resolve_push_transaction(&partial.work, "origin", "main")
        .is_err());

    let promisor = fixture();
    let pack = promisor.work.join(".git/objects/pack");
    std::fs::create_dir_all(&pack).unwrap();
    std::fs::write(pack.join("agent-controlled.promisor"), b"").unwrap();
    assert!(promisor
        .broker()
        .resolve_push_transaction(&promisor.work, "origin", "main")
        .is_err());
}

#[test]
fn linked_worktrees_fail_closed() {
    let f = fixture();
    let linked = f.work.parent().unwrap().join("linked");
    let output = Command::new("git")
        .args(["worktree", "add", "-b", "linked-test"])
        .arg(&linked)
        .current_dir(&f.work)
        .output()
        .expect("git worktree");
    assert!(
        output.status.success(),
        "git worktree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(f
        .broker()
        .resolve_push_transaction(&linked, "origin", "linked-test")
        .is_err());
}

#[test]
fn local_remotes_are_rejected_without_an_explicit_test_opt_in() {
    let f = fixture();
    assert!(PushBroker::default()
        .resolve_push_transaction(&f.work, "origin", "main")
        .is_err());
}
