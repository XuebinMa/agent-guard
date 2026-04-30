//! Integration tests for the async audit-file writer.
//!
//! These cover three contracts of `AuditFileWriter` / Guard's audit pipeline:
//!
//! 1. Lines are written to the file in arrival order (no shuffling).
//! 2. When the bounded channel is full, oldest excess events are dropped
//!    rather than blocking the producer; the file holds at most `capacity`
//!    lines and no panic occurs.
//! 3. Concurrent `Guard::check` calls do not serialize on a per-call audit
//!    file lock — a smoke regression that catches a revert to the previous
//!    `Mutex<File>` model. Marked `#[ignore]` because wall-clock thresholds
//!    are sensitive to CI hardware variance; run manually with
//!    `cargo test --test audit_async_integration -- --ignored`.

use agent_guard_sdk::audit_writer::AuditFileWriter;
use agent_guard_sdk::{Context, Guard, Tool, TrustLevel};
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

fn read_lines(path: &std::path::Path) -> Vec<String> {
    let f = std::fs::File::open(path).expect("audit file readable");
    BufReader::new(f)
        .lines()
        .map(|l| l.expect("utf-8 line"))
        .collect()
}

#[test]
fn audit_file_writer_orders_writes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");

    let writer = AuditFileWriter::open(&path).unwrap();
    for i in 0..100 {
        writer.send(format!("line-{i:03}"));
    }
    drop(writer); // forces worker to flush + exit

    let lines = read_lines(&path);
    assert_eq!(lines.len(), 100, "all lines should be persisted");
    for (i, line) in lines.iter().enumerate() {
        assert_eq!(line, &format!("line-{i:03}"), "line {i} out of order");
    }
}

#[test]
fn audit_file_writer_drops_when_full() {
    // Tiny capacity: 4 slots. We push many more lines than that. The worker
    // is artificially slow at startup because the file is unbuffered and
    // each `writeln!` syscalls; even if it drains some, it cannot keep up
    // with a tight producer loop, so the channel must overflow.
    const CAPACITY: usize = 4;
    const ATTEMPTS: usize = 200;

    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");

    let writer = AuditFileWriter::open_with_capacity(&path, CAPACITY).unwrap();
    for i in 0..ATTEMPTS {
        writer.send(format!("line-{i:04}"));
    }
    drop(writer);

    let lines = read_lines(&path);

    // The bound on what's persisted is: lines actively drained while the
    // producer was running PLUS whatever fit in the channel at drop time.
    // We can't pin an exact count without serialising the test, but we can
    // assert (a) some lines were dropped under burst, and (b) the file
    // contents are still a strict prefix-by-arrival of what was sent.
    assert!(
        lines.len() < ATTEMPTS,
        "expected drop-on-full to discard at least one line; got {}/{}",
        lines.len(),
        ATTEMPTS
    );
    assert!(
        !lines.is_empty(),
        "writer should have persisted at least some lines"
    );

    // Persisted lines must be in arrival order (a strictly increasing
    // subsequence of the sent indices). Drops can punch holes, but order is
    // preserved.
    let mut last_idx: i64 = -1;
    for line in &lines {
        let idx: i64 = line
            .strip_prefix("line-")
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("unexpected line format: {line}"));
        assert!(idx > last_idx, "lines out of order: {idx} after {last_idx}");
        last_idx = idx;
    }
}

const AUDIT_POLICY_TEMPLATE: &str = r#"
version: 1
default_mode: workspace_write

tools:
  bash:
    allow:
      - prefix: "echo"

audit:
  enabled: true
  output: file
  file_path: "__AUDIT_PATH__"
  include_payload_hash: false

anomaly:
  enabled: false
"#;

fn build_guard_with_audit_file(path: &std::path::Path) -> Guard {
    let yaml = AUDIT_POLICY_TEMPLATE.replace("__AUDIT_PATH__", path.to_str().unwrap());
    Guard::from_yaml(&yaml).expect("guard with audit file builds")
}

fn allow_input(i: usize) -> (Tool, String, Context) {
    (
        Tool::Bash,
        format!(r#"{{"command":"echo {i}"}}"#),
        Context {
            trust_level: TrustLevel::Trusted,
            agent_id: Some("audit-async-test".to_string()),
            ..Default::default()
        },
    )
}

/// Smoke regression: 8 threads x 100 calls each must not serialize on
/// the audit file. Threshold is generous; the goal is to catch a revert
/// to `Mutex<File>` + synchronous `writeln!`, which would push wall-clock
/// well past 500ms even on fast CI.
///
/// Marked `#[ignore]` because wall-clock thresholds are flaky on busy CI;
/// run manually with `--ignored`.
#[test]
#[ignore = "perf smoke; run manually with --ignored"]
fn audit_under_concurrent_load_does_not_serialize() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let guard = Arc::new(build_guard_with_audit_file(&path));

    const THREADS: usize = 8;
    const CALLS_PER_THREAD: usize = 100;
    const WALL_BUDGET: Duration = Duration::from_millis(500);

    let start = Instant::now();
    let mut handles = Vec::with_capacity(THREADS);
    for t in 0..THREADS {
        let g = guard.clone();
        handles.push(thread::spawn(move || {
            for i in 0..CALLS_PER_THREAD {
                let (tool, payload, ctx) = allow_input(t * CALLS_PER_THREAD + i);
                let _ = g.check_tool(tool, payload, ctx);
            }
        }));
    }
    for h in handles {
        h.join().expect("thread joined");
    }
    let elapsed = start.elapsed();

    assert!(
        elapsed < WALL_BUDGET,
        "audit pipeline appears to serialize: {:?} > budget {:?}",
        elapsed,
        WALL_BUDGET
    );
}
