# CLAUDE.md — agent-guard-sdk

Scoped guidance for the integration hub. This **adds** to the root
[`CLAUDE.md`](../../CLAUDE.md); it does not repeat it. This is where the
`Guard` pipeline, the runtime decision types, and the release/security/parity
integration tests live — read the
[Testing Strategy](../../docs/concepts/testing-strategy.md) before changing
anything here.

## What this crate is

The main integration point. `guard.rs` orchestrates the **Check → Filter →
Audit → Sandbox** pipeline; everything else is a stage or a governance feature
hanging off it:

- `guard.rs`, `runtime.rs`, `enforce.rs` — the decision + execution surface
  (`check` / `decide` / `run` / `execute`, `RuntimeDecision`, the execute
  result types).
- `sandbox_resolution.rs` — default backend selection + diagnosis (feeds
  `GATE 2`; must report `"none"` when no real backend is compiled in), plus
  `resolve_sandbox_by_name` (feeds `GATE 5`; mirrors the default gating
  exactly — notably `linux-seccomp` gates on the Cargo feature, NOT on
  `is_available()`, which is `true` on any Linux host).
- `anomaly.rs` — rate limiting + the deny fuse (agent lock-out).
- `audit_writer.rs`, `siem.rs` — append-only JSONL audit records and webhook
  export (async; uses the tokio runtime).
- `provenance.rs`, `policy_signing.rs` — opt-in Ed25519 execution receipts
  (require a signing key) and policy signing/verification.
- `content_filter.rs` — content-layer stage, behind the off-by-default
  `content` feature: outbound (`write_file` content / `http_request` body,
  rewritten on the execution path) and input (`Guard::check_content` over the
  top-level `input_content:` block; Mask hands the redacted text back to the
  host — the Guard never performs the downstream LLM call).
- `metrics.rs` — Prometheus metrics. `doctor.rs` — host-boundary report.

## Invariants

1. **The pipeline order is the contract.** Policy decision → validator filter →
   audit → sandboxed execution. Do not let a later stage silently override an
   earlier deny, and do not execute before the decision is `allow`.
2. **Fail closed.** Any error in enforcement, sandbox setup, or execution is a
   hard error, never a silent allow — locked by `GATE 1` in
   [`tests/release_gate.rs`](tests/release_gate.rs). New failure paths get a
   test proving they deny/error.
3. **Feature flags pass through.** This crate's `content` / `seccomp` /
   `landlock` / `macos-sandbox` / `windows-*` features just re-export the
   sandbox/validators features, so `--all-features` here pulls the platform
   backends in. The workspace test/build commands compile this crate with
   `--all-features`; the per-OS sandbox backends still only *run* on their OS.
4. **This is the parity source of truth.** The Python and Node bindings wrap the
   types defined here. A change to the decision shape, `DecisionCode`, or
   `check`/`decide`/`run`/`execute` semantics ripples to both bindings and the
   parity scenarios — see [Cross-Language Parity](../../docs/concepts/cross-language-parity.md).

## Tests: the suite in `tests/` is the spec

Most of the project's behavioural contract is the integration suite here — new
behaviour lands as a test in the right file, not a new bespoke harness:

- [`tests/release_gate.rs`](tests/release_gate.rs) — release-blocking invariants
  (`GATE 1-5`; 5 = by-name backend selection truthfulness). Add an invariant
  as the next `GATE`.
- [`tests/security_regression.rs`](tests/security_regression.rs) — one test per
  closed attack class; cite the PR. **Every closed bypass gets a lock here.**
- `tests/parity.rs`, `tests/content_enforcement.rs`, `tests/approval_resume.rs`,
  `tests/execute_integration.rs`, `tests/audit_async_integration.rs`,
  `tests/stress_*.rs`, … — the composed end-to-end behaviour.

Run the crate's tests (real engine — do not mock the policy engine or sandbox):

```bash
cargo test -p agent-guard-sdk --all-features
cargo test -p agent-guard-sdk --test security_regression   # the attack-class locks
```

Cross-language and definition-of-done obligations are in
[`CONTRIBUTING.md`](../../CONTRIBUTING.md).
</content>
