//! Independent local writers must preserve complete JSONL event frames.
use agent_guard_sdk::{approval::ApprovalLedger, audit_writer::AuditFileWriter};
use std::collections::HashSet;
use std::sync::{Arc, Barrier};

#[test]
fn concurrent_audit_writers_preserve_every_json_frame() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let barrier = Arc::new(Barrier::new(12));
    let workers: Vec<_> = (0..12).map(|worker| {
        let path = path.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            let writer = AuditFileWriter::open_with_capacity(&path, 200).unwrap();
            barrier.wait();
            for item in 0..100 {
                writer.send(serde_json::json!({"id": format!("{worker}-{item}"), "fixture": "x".repeat(2048)}).to_string());
            }
            drop(writer);
        })
    }).collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let contents = std::fs::read_to_string(path).unwrap();
    let mut ids = HashSet::new();
    for line in contents.lines() {
        let row: serde_json::Value = serde_json::from_str(line).expect("intact audit JSON frame");
        assert!(ids.insert(row["id"].as_str().unwrap().to_string()));
    }
    assert_eq!(ids.len(), 1200);
}

#[test]
fn concurrent_approval_writers_preserve_every_pending_request() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("approvals.jsonl");
    let barrier = Arc::new(Barrier::new(12));
    let workers: Vec<_> = (0..12)
        .map(|worker| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let ledger = ApprovalLedger::open(path);
                barrier.wait();
                for item in 0..100 {
                    ledger
                        .create_pending(
                            format!("{worker}-{item}"),
                            "fixture",
                            "hash",
                            "x".repeat(2048),
                            None,
                            None,
                        )
                        .unwrap();
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let contents = std::fs::read_to_string(&path).unwrap();
    assert_eq!(contents.lines().count(), 1200);
    for line in contents.lines() {
        serde_json::from_str::<serde_json::Value>(line).expect("intact approval JSON frame");
    }
    assert_eq!(
        ApprovalLedger::open(path).list_pending().unwrap().len(),
        1200
    );
}

// Run the same public ledger API in independent processes, not just threads.
#[test]
fn jsonl_child_writer() {
    let Ok(path) = std::env::var("AGENT_GUARD_JSONL_TEST_PATH") else {
        return;
    };
    let id = std::env::var("AGENT_GUARD_JSONL_TEST_ID").unwrap();
    let ledger = ApprovalLedger::open(path);
    for item in 0..100 {
        ledger
            .create_pending(
                format!("{id}-{item}"),
                "fixture",
                "hash",
                "x".repeat(4096),
                None,
                None,
            )
            .unwrap();
    }
}

#[test]
fn independent_processes_preserve_complete_approval_frames() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("process-approvals.jsonl");
    let mut children: Vec<_> = (0..4)
        .map(|id| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "jsonl_child_writer"])
                .env("AGENT_GUARD_JSONL_TEST_PATH", &path)
                .env("AGENT_GUARD_JSONL_TEST_ID", id.to_string())
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    for child in &mut children {
        assert!(child.wait().unwrap().success());
    }
    assert_eq!(
        ApprovalLedger::open(&path).list_pending().unwrap().len(),
        400
    );
    for line in std::fs::read_to_string(path).unwrap().lines() {
        serde_json::from_str::<serde_json::Value>(line).expect("intact process-written frame");
    }
}
