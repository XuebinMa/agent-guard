//! Criterion bench for the audit-write hot path.
//!
//! Measures `Guard::check` end-to-end with `audit.enabled = true`, comparing:
//!
//! - `audit_write_file`   — `output: file` pointed at a tempfile. The hot path
//!   here is the producer-side enqueue into `AuditFileWriter`'s bounded
//!   channel; the worker thread flushes asynchronously. This is the path
//!   S2-2 (async audit writer) optimized.
//! - `audit_write_stdout` — `output: stdout`. Acts as a control bench so the
//!   file-output number is comparable to a baseline that doesn't exercise
//!   the writer thread.
//!
//! Both benches use a tiny no-rule policy so the bench dominates audit cost,
//! not policy evaluation. Output goes to a process-local sink (file or, for
//! the control, stdout — redirected when criterion runs).
//!
//! Run: cargo bench -p agent-guard-sdk --bench audit_write

use agent_guard_sdk::{Context, Guard, GuardInput, Tool, TrustLevel};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tempfile::NamedTempFile;

fn policy_yaml(audit_block: &str) -> String {
    // Bench runs millions of iterations against one Guard instance; the
    // default rate limit (30 calls / 60s) would flip every iteration after
    // the first ~30 to a synthetic Deny path and skew the measurement off
    // the audit hot path. Disabling anomaly keeps every iteration on the
    // Allow → write_audit path.
    format!(
        r#"
version: 1
default_mode: workspace_write

tools:
  bash:
    mode: workspace_write
    allow:
      - prefix: "echo"

anomaly:
  enabled: false

audit:
{audit_block}
"#
    )
}

fn make_input() -> GuardInput {
    GuardInput {
        tool: Tool::Bash,
        payload: r#"{"command":"echo hello"}"#.to_string(),
        context: Context {
            agent_id: Some("bench-agent".into()),
            session_id: Some("bench-session".into()),
            actor: Some("bench-actor".into()),
            trust_level: TrustLevel::Trusted,
            working_directory: Some("/tmp".into()),
        },
    }
}

fn bench_audit_write(c: &mut Criterion) {
    // File audit path. Tempfile is cleaned up when `_tmp` drops at the end of
    // the bench; the path must remain valid for the duration of the bench.
    let tmp = NamedTempFile::new().expect("create tempfile");
    let tmp_path = tmp.path().to_string_lossy().into_owned();
    let file_yaml = policy_yaml(&format!(
        "  enabled: true\n  output: file\n  file_path: \"{}\"\n",
        tmp_path
    ));
    let guard_file = Guard::from_yaml(&file_yaml).expect("policy parse failed");
    let input = make_input();

    c.bench_function("audit_write_file", |b| {
        b.iter(|| {
            let decision = guard_file.check(black_box(&input));
            black_box(decision);
        })
    });

    // Control: stdout output. The real `println!` path is what we want to
    // measure as a baseline, but printing millions of JSONL lines to the
    // terminal would balloon CI logs. We redirect stdout to /dev/null at
    // the file-descriptor level for the duration of the bench, so the
    // `println!` syscall cost is preserved but the bytes go nowhere.
    let stdout_yaml = policy_yaml("  enabled: true\n  output: stdout\n");
    let guard_stdout = Guard::from_yaml(&stdout_yaml).expect("policy parse failed");

    c.bench_function("audit_write_stdout", |b| {
        // Redirect only for the timing closure so criterion's own output
        // (analysis summary, regression report) still reaches the terminal.
        let _redirect = StdoutRedirect::to_devnull();
        b.iter(|| {
            let decision = guard_stdout.check(black_box(&input));
            black_box(decision);
        });
        drop(_redirect);
    });

    // Hold tmpfile until both benches have finished.
    drop(tmp);
}

/// Redirect stdout (fd 1) to `/dev/null` for the lifetime of this guard.
///
/// Used during the `audit_write_stdout` bench so the millions of `println!`
/// calls don't flood the terminal / CI log. The original stdout fd is
/// preserved and restored on Drop. Unix-only; on other platforms it's a
/// no-op so the bench still runs (just with the noise).
struct StdoutRedirect {
    #[cfg(unix)]
    saved: Option<libc::c_int>,
}

impl StdoutRedirect {
    #[cfg(unix)]
    fn to_devnull() -> Self {
        // Best-effort: any error here downgrades to "no redirect" so the
        // bench still runs. We're not going to fail a perf bench because
        // /dev/null is unavailable.
        unsafe {
            // Flush before swapping the fd so any buffered output goes to
            // the real terminal first.
            libc::fflush(std::ptr::null_mut());
            let saved = libc::dup(1);
            if saved < 0 {
                return Self { saved: None };
            }
            let null_path = c"/dev/null".as_ptr();
            let null_fd = libc::open(null_path, libc::O_WRONLY);
            if null_fd < 0 {
                libc::close(saved);
                return Self { saved: None };
            }
            if libc::dup2(null_fd, 1) < 0 {
                libc::close(null_fd);
                libc::close(saved);
                return Self { saved: None };
            }
            libc::close(null_fd);
            Self { saved: Some(saved) }
        }
    }

    #[cfg(not(unix))]
    fn to_devnull() -> Self {
        Self {}
    }
}

impl Drop for StdoutRedirect {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            if let Some(saved) = self.saved.take() {
                libc::fflush(std::ptr::null_mut());
                libc::dup2(saved, 1);
                libc::close(saved);
            }
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = bench_audit_write
}
criterion_main!(benches);
