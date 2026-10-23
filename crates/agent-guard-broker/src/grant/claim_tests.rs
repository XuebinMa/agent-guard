use super::*;
use std::process::{Command, Stdio};
use std::time::{Duration as Wait, Instant};

const ROOT: &str = "AGENT_GUARD_OWNED_INTERRUPTED_CLAIM_ROOT";

#[test]
fn owned_interrupted_claim() {
    let Some(root) = std::env::var_os(ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let id = std::env::var("AGENT_GUARD_OWNED_INTERRUPTED_CLAIM_ID").unwrap();
    reserve_claim(&root.join("spent"), &id).unwrap();
    // Leave the real production reservation without archival or unwinding.
    std::process::exit(27);
}

#[test]
fn process_exit_after_reservation_cannot_restore_authority() {
    let dir = tempfile::tempdir().unwrap();
    let transaction = PushTransaction {
        remote: "origin".into(),
        remote_url: "https://example.invalid/repo.git".into(),
        branch: "main".into(),
        local_oid: "bbbb".into(),
        remote_oid: None,
        kind: crate::transaction::RefUpdateKind::Create,
        added_commits: Some(vec!["bbbb".into()]),
    };
    let id = issue_grant(
        dir.path(),
        &transaction,
        "policy",
        "fixture",
        Duration::minutes(5),
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("spent")).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "grant::claim_tests::owned_interrupted_claim",
            "--nocapture",
        ])
        .env(ROOT, dir.path())
        .env("AGENT_GUARD_OWNED_INTERRUPTED_CLAIM_ID", &id)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let until = Instant::now() + Wait::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            panic!("bounded owned interruption fixture timed out");
        }
        std::thread::sleep(Wait::from_millis(10));
    };
    assert_eq!(status.code(), Some(27));
    assert!(grant_path(dir.path(), &id).unwrap().is_file());
    assert!(!grant_path(&dir.path().join("spent"), &id).unwrap().exists());
    assert!(grant_was_spent(dir.path(), &id));
    assert!(matches!(
        spend_grant(dir.path(), &id, &transaction, "policy", Utc::now()),
        Err(GrantError::NotFound { .. })
    ));
}

#[cfg(unix)]
#[test]
fn consumption_marker_and_archive_directory_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let spent = dir.path().join("spent");
    std::fs::create_dir(&spent).unwrap();
    restrict_directory(&spent).unwrap();
    reserve_claim(&spent, "fixture").unwrap();
    assert_eq!(
        std::fs::metadata(&spent).unwrap().permissions().mode() & 0o077,
        0
    );
    assert_eq!(
        std::fs::metadata(claim_marker_path(&spent, "fixture"))
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );
}
