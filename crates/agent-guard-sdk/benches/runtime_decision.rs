//! Criterion bench for `Guard::decide` (the `RuntimeDecision` mapping path).
//!
//! Covers the four runtime-decision shapes the SDK produces for representative
//! inputs:
//!
//! - `runtime_decide_bash_allow`  — Bash allow → `Execute`
//! - `runtime_decide_bash_deny`   — Bash deny  → `Deny`
//! - `runtime_decide_http_mutation` — POST    → `Execute` (guard-owned)
//! - `runtime_decide_http_read`     — GET     → `Handoff` (host-owned)
//!
//! The Guard is built once outside the loop. Audit is disabled so we only
//! time the policy + decision-mapping path.
//!
//! Run: cargo bench -p agent-guard-sdk --bench runtime_decision

use agent_guard_sdk::{Context, Guard, GuardInput, Tool, TrustLevel};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

const POLICY_YAML: &str = r#"
version: 1
default_mode: workspace_write

tools:
  bash:
    mode: workspace_write
    deny:
      - prefix: "rm -rf"
      - prefix: "sudo"
    allow:
      - prefix: "echo"
      - prefix: "cargo"
      - prefix: "ls"
  http_request:
    mode: workspace_write
    allow:
      - prefix: "https://api.example.com"

anomaly:
  enabled: false

audit:
  enabled: false
"#;

fn ctx() -> Context {
    Context {
        agent_id: Some("bench-agent".into()),
        session_id: Some("bench-session".into()),
        actor: Some("bench-actor".into()),
        trust_level: TrustLevel::Trusted,
        working_directory: Some("/tmp".into()),
    }
}

fn bench_runtime_decision(c: &mut Criterion) {
    let guard = Guard::from_yaml(POLICY_YAML).expect("policy parse failed");

    let bash_allow = GuardInput {
        tool: Tool::Bash,
        payload: r#"{"command":"echo hello"}"#.into(),
        context: ctx(),
    };
    c.bench_function("runtime_decide_bash_allow", |b| {
        b.iter(|| {
            let d = guard.decide(black_box(&bash_allow));
            black_box(d);
        })
    });

    let bash_deny = GuardInput {
        tool: Tool::Bash,
        payload: r#"{"command":"rm -rf /tmp/build"}"#.into(),
        context: ctx(),
    };
    c.bench_function("runtime_decide_bash_deny", |b| {
        b.iter(|| {
            let d = guard.decide(black_box(&bash_deny));
            black_box(d);
        })
    });

    // Mutation HTTP — POST is recognized as guard-owned execution and should
    // map to `RuntimeDecision::Execute` on Allow.
    let http_mutation = GuardInput {
        tool: Tool::HttpRequest,
        payload: r#"{"method":"POST","url":"https://api.example.com/v1/items","body":"{}"}"#.into(),
        context: ctx(),
    };
    c.bench_function("runtime_decide_http_mutation", |b| {
        b.iter(|| {
            let d = guard.decide(black_box(&http_mutation));
            black_box(d);
        })
    });

    // Read HTTP — GET maps to `RuntimeDecision::Handoff` on Allow because
    // read traffic is host-owned in the runtime split.
    let http_read = GuardInput {
        tool: Tool::HttpRequest,
        payload: r#"{"method":"GET","url":"https://api.example.com/v1/items"}"#.into(),
        context: ctx(),
    };
    c.bench_function("runtime_decide_http_read", |b| {
        b.iter(|| {
            let d = guard.decide(black_box(&http_read));
            black_box(d);
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = bench_runtime_decision
}
criterion_main!(benches);
