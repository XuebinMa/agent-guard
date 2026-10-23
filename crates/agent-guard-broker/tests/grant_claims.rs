//! Permanent one-use state, independent of the retained grant archive.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use agent_guard_broker::{
    issue_grant, spend_grant, GrantError, PushAttempt, PushBroker, PushTransaction, RefUpdateKind,
};
use chrono::{Duration as Ttl, Utc};

fn transaction() -> PushTransaction {
    PushTransaction {
        remote: "origin".into(),
        remote_url: "https://example.invalid/repo.git".into(),
        branch: "main".into(),
        local_oid: "bbbb".into(),
        remote_oid: Some("aaaa".into()),
        kind: RefUpdateKind::FastForward,
        added_commits: Some(vec!["bbbb".into()]),
    }
}

fn issue(dir: &Path) -> String {
    issue_grant(dir, &transaction(), "policy", "fixture", Ttl::minutes(5)).unwrap()
}

fn pending(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.json"))
}

fn archived(dir: &Path, id: &str) -> PathBuf {
    dir.join("spent").join(format!("{id}.json"))
}

fn marker(dir: &Path, id: &str) -> PathBuf {
    dir.join("spent").join(format!("claim-{id}.consumed"))
}

fn unavailable(result: Result<agent_guard_broker::PushGrant, GrantError>) {
    assert!(
        matches!(result, Err(GrantError::NotFound { .. })),
        "{result:?}"
    );
}

#[test]
fn empty_and_partial_markers_refuse_an_unarchived_grant() {
    for bytes in [b"".as_slice(), b"interrupted".as_slice()] {
        let dir = tempfile::tempdir().unwrap();
        let id = issue(dir.path());
        std::fs::create_dir(dir.path().join("spent")).unwrap();
        std::fs::write(marker(dir.path(), &id), bytes).unwrap();
        unavailable(spend_grant(
            dir.path(),
            &id,
            &transaction(),
            "policy",
            Utc::now(),
        ));
        assert!(pending(dir.path(), &id).is_file());
        assert!(!archived(dir.path(), &id).exists());
    }
}

#[test]
fn restoring_only_unspent_json_does_not_revive_a_consumed_id() {
    let dir = tempfile::tempdir().unwrap();
    let id = issue(dir.path());
    let original = std::fs::read(pending(dir.path(), &id)).unwrap();
    spend_grant(dir.path(), &id, &transaction(), "policy", Utc::now()).unwrap();
    assert!(marker(dir.path(), &id).is_file());
    std::fs::remove_file(archived(dir.path(), &id)).unwrap();
    std::fs::write(pending(dir.path(), &id), original).unwrap();
    unavailable(spend_grant(
        dir.path(),
        &id,
        &transaction(),
        "policy",
        Utc::now(),
    ));
    assert!(marker(dir.path(), &id).is_file());
}

#[test]
fn legacy_archive_blocks_recreated_unspent_json_without_being_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let id = issue(dir.path());
    std::fs::create_dir(dir.path().join("spent")).unwrap();
    let evidence = b"retained legacy evidence: do not replace";
    std::fs::write(archived(dir.path(), &id), evidence).unwrap();
    unavailable(spend_grant(
        dir.path(),
        &id,
        &transaction(),
        "policy",
        Utc::now(),
    ));
    assert_eq!(std::fs::read(archived(dir.path(), &id)).unwrap(), evidence);
    assert!(pending(dir.path(), &id).is_file());
}

#[test]
fn invalid_presentations_leave_a_permanent_marker() {
    for case in ["policy", "expired", "corrupt"] {
        let dir = tempfile::tempdir().unwrap();
        let id = issue(dir.path());
        let original = std::fs::read(pending(dir.path(), &id)).unwrap();
        if case == "corrupt" {
            std::fs::write(pending(dir.path(), &id), b"{").unwrap();
        }
        let now = Utc::now()
            + if case == "expired" {
                Ttl::hours(1)
            } else {
                Ttl::zero()
            };
        let policy = if case == "policy" {
            "changed"
        } else {
            "policy"
        };
        let result = spend_grant(dir.path(), &id, &transaction(), policy, now);
        assert!(result.is_err(), "{case}");
        assert!(marker(dir.path(), &id).is_file(), "{case}");
        std::fs::write(pending(dir.path(), &id), original).unwrap();
        unavailable(spend_grant(
            dir.path(),
            &id,
            &transaction(),
            "policy",
            Utc::now(),
        ));
    }
}

#[test]
fn missing_source_archive_failure_still_retains_the_consumed_id_in_a_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let id = issue(dir.path());
    std::fs::remove_file(pending(dir.path(), &id)).unwrap();
    let record = PushBroker::default().execute_push_with_receipt(
        &dir.path().join("not-a-repository"),
        dir.path(),
        &id,
        "policy",
        Utc::now(),
        None,
    );
    assert!(matches!(record.attempt, PushAttempt::Refused { .. }));
    assert_eq!(record.grant_id.as_deref(), Some(id.as_str()));
    assert!(record.transaction.is_none());
    assert!(marker(dir.path(), &id).is_file());
    assert!(!archived(dir.path(), &id).exists());
}

#[test]
fn marker_only_interruption_is_receipted_before_repository_inspection() {
    let dir = tempfile::tempdir().unwrap();
    let id = issue(dir.path());
    std::fs::create_dir(dir.path().join("spent")).unwrap();
    std::fs::write(marker(dir.path(), &id), b"").unwrap();
    let record = PushBroker::default().execute_push_with_receipt(
        &dir.path().join("not-a-repository"),
        dir.path(),
        &id,
        "policy",
        Utc::now(),
        None,
    );
    assert!(matches!(record.attempt, PushAttempt::Refused { .. }));
    assert_eq!(record.grant_id.as_deref(), Some(id.as_str()));
    assert!(record.transaction.is_none());
    assert!(pending(dir.path(), &id).is_file());
}

#[test]
fn read_failure_after_archival_keeps_consumption_and_refuses_a_restored_source() {
    let dir = tempfile::tempdir().unwrap();
    let id = issue(dir.path());
    let original = std::fs::read(pending(dir.path(), &id)).unwrap();
    std::fs::remove_file(pending(dir.path(), &id)).unwrap();
    std::fs::create_dir(pending(dir.path(), &id)).unwrap();
    let record = PushBroker::default().execute_push_with_receipt(
        &dir.path().join("not-a-repository"),
        dir.path(),
        &id,
        "policy",
        Utc::now(),
        None,
    );
    assert!(matches!(record.attempt, PushAttempt::Refused { .. }));
    assert_eq!(record.grant_id.as_deref(), Some(id.as_str()));
    assert!(record.transaction.is_none());
    assert!(
        !pending(dir.path(), &id).exists(),
        "archival actually succeeded"
    );
    assert!(archived(dir.path(), &id).is_dir());
    assert!(marker(dir.path(), &id).is_file());
    std::fs::remove_dir(archived(dir.path(), &id)).unwrap();
    std::fs::write(pending(dir.path(), &id), original).unwrap();
    unavailable(spend_grant(
        dir.path(),
        &id,
        &transaction(),
        "policy",
        Utc::now(),
    ));
}

#[test]
fn dotted_ids_have_distinct_consumption_slots() {
    let dir = tempfile::tempdir().unwrap();
    let issued = issue(dir.path());
    let original = std::fs::read(pending(dir.path(), &issued)).unwrap();
    for id in ["fixture.first", "fixture.second"] {
        let mut record: agent_guard_broker::PushGrant = serde_json::from_slice(&original).unwrap();
        record.grant_id = id.into();
        std::fs::write(
            pending(dir.path(), id),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        spend_grant(dir.path(), id, &transaction(), "policy", Utc::now()).unwrap();
        assert!(marker(dir.path(), id).is_file());
    }
}

#[cfg(unix)]
#[test]
fn dangling_legacy_archive_is_consumed_not_followed_or_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let id = issue(dir.path());
    std::fs::create_dir(dir.path().join("spent")).unwrap();
    std::os::unix::fs::symlink(dir.path().join("absent"), archived(dir.path(), &id)).unwrap();
    unavailable(spend_grant(
        dir.path(),
        &id,
        &transaction(),
        "policy",
        Utc::now(),
    ));
    assert!(std::fs::symlink_metadata(archived(dir.path(), &id))
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(pending(dir.path(), &id).is_file());
}

struct OwnedChildren(Vec<Child>);

impl Drop for OwnedChildren {
    fn drop(&mut self) {
        for child in &mut self.0 {
            if !matches!(child.try_wait(), Ok(Some(_))) {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

const CHILD_ROOT: &str = "AGENT_GUARD_OWNED_GRANT_RACER_ROOT";

#[test]
fn owned_process_claim() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let id = std::env::var("AGENT_GUARD_OWNED_GRANT_ID").unwrap();
    let slot = std::env::var("AGENT_GUARD_OWNED_GRANT_SLOT").unwrap();
    std::fs::write(root.join(format!("ready-{slot}")), b"ready").unwrap();
    let until = Instant::now() + Duration::from_secs(15);
    while !root.join("go").exists() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(root.join("go").is_file(), "owned fixture start deadline");
    let code = match spend_grant(
        &root.join("grants"),
        &id,
        &transaction(),
        "policy",
        Utc::now(),
    ) {
        Ok(_) => 0,
        Err(GrantError::NotFound { .. }) => 2,
        Err(error) => panic!("unexpected fixture claim error: {error}"),
    };
    std::process::exit(code);
}

#[test]
fn independent_processes_have_exactly_one_claim_winner() {
    const RACERS: usize = 8;
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("grants");
    let id = issue(&dir);
    let mut children = OwnedChildren(Vec::new());
    for slot in 0..RACERS {
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "owned_process_claim", "--nocapture"])
            .env(CHILD_ROOT, root.path())
            .env("AGENT_GUARD_OWNED_GRANT_ID", &id)
            .env("AGENT_GUARD_OWNED_GRANT_SLOT", slot.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        children.0.push(child);
    }
    let until = Instant::now() + Duration::from_secs(10);
    while !(0..RACERS).all(|i| root.path().join(format!("ready-{i}")).is_file()) {
        assert!(
            Instant::now() < until,
            "all owned processes must actually start"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    std::fs::write(root.path().join("go"), b"start").unwrap();
    let until = Instant::now() + Duration::from_secs(10);
    let mut winners = 0;
    for child in &mut children.0 {
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < until, "bounded owned claim fixture");
            std::thread::sleep(Duration::from_millis(10));
        };
        match status.code() {
            Some(0) => winners += 1,
            Some(2) => {}
            other => panic!("unexpected owned child result: {other:?}"),
        }
    }
    assert_eq!(winners, 1);
    assert!(marker(&dir, &id).is_file());
    assert!(archived(&dir, &id).is_file());
}
