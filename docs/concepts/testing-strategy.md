# Testing Strategy

`agent-guard` sits between an agent's tool intent and a real side effect — a
shell command, a file write, an outbound mutation. A regression here does not
produce a wrong number on a screen; it lets a payload through. That raises the
bar for what "tested" means, and it changes *when* tests get written.

This document is the contract for that. It explains the philosophy
(tests drive the work, not the other way around), the layers we actually run,
where each one lives, and what "done" means before a change can merge. It is
the long-form companion to the [Build & Test Commands in
`CLAUDE.md`](../../CLAUDE.md) and the [Tests section in
`CONTRIBUTING.md`](../../CONTRIBUTING.md); when they disagree, those two are
the operational source of truth and this doc is the *why*.

## Thesis: the test is the specification of the boundary

For a security boundary, the test is not a check you add after the code works.
It *is* the description of where the boundary is. The behaviour we care about —
"this class of command is denied", "this traversal is normalised before it can
escape the workspace", "a sandbox failure blocks execution instead of falling
through" — only exists to the extent there is a test that fails when it breaks.

So the default order of work is inverted from a typical library:

1. **Write the failing test first.** A new defense starts as a scenario that
   currently lets the payload through (or a parity scenario the runners
   disagree on). A bug fix starts as a regression test that reproduces the
   bypass and currently goes green where it should go red.
2. **Make it pass with the smallest change** that closes the boundary.
3. **Lock it.** The test stays forever as the thing that screams if the
   boundary moves back.

This is already how the repo is maintained — `security_regression.rs` names the
PR that closed each attack class, and `release_gate.rs` encodes four invariants
as `GATE 1..4`. This document makes that practice explicit so it is followed by
default rather than rediscovered per change.

## Principles

1. **The test is the spec.** If a behaviour matters, there is a test that fails
   when it regresses. If there is no such test, the behaviour is not guaranteed,
   regardless of what the code looks like.
2. **Every closed bypass earns a permanent lock.** A fix without a regression
   test is half a fix. The lock lives in
   [`security_regression.rs`](../../crates/agent-guard-sdk/tests/security_regression.rs)
   when it is an attack class, or next to the code when it is a narrower bug.
3. **Invariants are gates, not suggestions.** The properties that must *never*
   regress — fail-closed on sandbox error, truthful backend selection, the
   negative security boundary, receipt integrity — are encoded as the `GATE`
   tests in
   [`release_gate.rs`](../../crates/agent-guard-sdk/tests/release_gate.rs).
   You do not weaken a gate to make CI green; you fix the code or you change the
   gate deliberately, with review, as a documented decision.
4. **Run against the real engine.** Do not mock the policy engine, the
   validators, or the sandbox trait in behaviour tests. A mock tests your
   understanding of the boundary, not the boundary. Construct a real `Guard`
   from real YAML and assert on the real decision.
5. **Cross-language behaviour is a contract.** A decision is the same decision
   in Rust, Python, and Node, or it is a bug. One scenario, three runners — see
   the [parity section](#cross-language-parity) below.
6. **Fail closed, and test the failure.** When something cannot be evaluated
   safely — sandbox init failure, invalid signature in check mode, unparseable
   policy — the safe outcome is *deny/error*, and there is a test asserting it
   denies rather than silently allowing.

## The layers, and where they live

| Layer | Location | What it proves | When you add one |
| :--- | :--- | :--- | :--- |
| **Unit** | `src/tests.rs` / inline `#[cfg(test)] mod tests` | A function does what it claims (pattern match, path normalisation, classification) | Any new branch or edge in core/validators/sdk logic |
| **Integration** | `crates/<crate>/tests/*.rs` | Components compose correctly through a real `Guard` | New end-to-end behaviour spanning policy → validator → audit → sandbox |
| **Gate** | [`agent-guard-sdk/tests/release_gate.rs`](../../crates/agent-guard-sdk/tests/release_gate.rs) | A release-blocking invariant still holds | A new property that must *never* regress |
| **Security regression** | [`agent-guard-sdk/tests/security_regression.rs`](../../crates/agent-guard-sdk/tests/security_regression.rs) | A specific attack class stays closed | Every time you close a bypass (cite the PR) |
| **Stress** | `agent-guard-sdk/tests/stress_*.rs` | Behaviour holds under concurrency / resource pressure | Changes to shared state, locking, the deny fuse, async audit |
| **Sandbox per-OS** | `agent-guard-sandbox/tests/{seccomp,macos,windows_job}_integration.rs` | The real OS isolation actually blocks | Any change to a sandbox backend (run on that OS, with that feature) |
| **Cross-language parity** | [`tests/cross-language-parity/`](../../tests/cross-language-parity/) | Rust ≡ Python ≡ Node for the same input | Any change to decision shape, codes, or adapter mode semantics |
| **Python binding** | `agent-guard-python/tests/*.py` (pytest) | The PyO3 surface and adapters behave | Changes to the Python API, stubs, or langchain/openai adapters |
| **Node binding** | `agent-guard-node/test*.js`, `packages/agent-guard-plugin/test/` (node:test) | The napi-rs surface and adapters behave | Changes to the Node API or adapters |
| **Bench (non-blocking)** | `*/benches/*.rs` (criterion) | Performance trend visibility | Performance-sensitive changes to the hot path |
| **Supply-chain & docs** | CI: `cargo-deny`, `cargo-audit`, SBOM, `npm audit`; `scripts/check_docs.py` | No shipped vuln; docs don't drift from reality | Dependency changes; any docs edit |

Unit tests live next to the code; integration tests live in `tests/`. Security
regression cases go in the one suite named above so the attack surface is
auditable in a single file. These three rules come straight from
`CONTRIBUTING.md` and are not negotiable per-PR.

### The gate tests

[`release_gate.rs`](../../crates/agent-guard-sdk/tests/release_gate.rs) is the
spine of the whole strategy. Today it locks four invariants:

- **GATE 1 — Fail-closed robustness.** A sandbox that errors on `execute()`
  must surface a hard `Err`, never a silent allow. Tested with a `FailingSandbox`
  mock that always errors — the one place a mock is correct, because the point
  is to prove the SDK's reaction to a failing dependency, not the dependency.
- **GATE 2 — Platform selection consistency.** `Guard::default_sandbox()` and
  the diagnosis agree on the selected backend, and the selection is *truthful*:
  when no real isolation is compiled in, the backend reports `"none"` rather
  than claiming syscall filtering it does not provide.
- **GATE 3 — Negative security boundary.** A write outside the workspace (e.g.
  to `/etc`) must not succeed — manifested as an `Err`, a `Denied` outcome, or a
  non-zero exit code from the OS sandbox. The test skips cleanly when no real
  sandbox is active so it never produces a false green.
- **GATE 4 — Receipt integrity.** When a signing key is supplied, the
  tool-call → execution → signed `ExecutionReceipt` chain verifies end to end.
  Receipts are opt-in and require an explicit key; they are not emitted
  automatically for every call.

When you add an invariant that belongs to the release boundary, add it here as
the next `GATE`, with a doc comment that states the property in one sentence.

### Cross-language parity

The three bindings must return identical decisions for identical inputs. The
contract is data, not prose:

- [`tests/cross-language-parity/fixtures/scenarios.json`](../../tests/cross-language-parity/fixtures/scenarios.json)
  is the scenario set. **This file is the contract.**
- `runners/runner.py` and `runners/runner.js` execute every scenario in their
  language; `compare.py` diffs the outputs and fails on any divergence. CI runs
  this as the `parity-e2e` job.

If you touch any of the shapes called out in `CONTRIBUTING.md` — `Decision` /
`RuntimeDecision` / `RuntimeOutcome`, the `DecisionCode` enum, the
`check` / `decide` / `run` / `execute` semantics, or adapter mode handling —
then **all three runners change in the same PR and you add a scenario that
exercises the new behaviour.** A parity change that lands in one language only
is a regression even if every per-language test is green. See
[Cross-Language Parity](cross-language-parity.md) for the decision-identity
rules and [Adapter Contract](adapter-contract.md) for adapter mode semantics.

## The development loop, by change type

**Closing a new attack class / adding a deny rule**
1. Add the scenario to `security_regression.rs` (and to `scenarios.json` if the
   behaviour is cross-language). It should currently allow/execute the payload —
   i.e. fail in the unsafe direction.
2. Implement the validator/policy change until the test denies.
3. Confirm no other regression test flipped. Cite this work in the test's
   header comment list, matching the existing CVE-class numbering.

**Fixing a reported bypass**
1. Reproduce it as a failing test at the lowest layer that still captures the
   bug (unit if it's a parsing edge, integration if it spans the pipeline).
2. Fix until green. Do not amend the fix into the test commit in a way that
   hides the red→green transition — reviewers should be able to see the test
   fail without the fix.

**Changing a decision shape or code**
1. Add/adjust the parity scenario first.
2. Change all three runners and the core type in the same PR.
3. Keep `parity-e2e` green locally is not possible without the bindings built —
   see the local-vs-CI note below — so lean on the per-language tests locally
   and let CI run the full comparator.

**Touching a sandbox backend**
1. Add or extend the per-OS integration test
   (`seccomp_integration.rs` / `macos_integration.rs` /
   `windows_job_integration.rs`). These only mean anything on the matching OS
   with the matching feature flag.
2. Re-check `GATE 2` and `GATE 3` assumptions: if you change which backend is
   selected or what it blocks, the gates must still pass and stay truthful.
3. Never relabel a prototype/fallback backend as full isolation — the docs
   linter and the gate both enforce that the Linux baseline is described as the
   prototype wrapper it currently is, not shipped seccomp-bpf enforcement.

**Performance-sensitive change to the hot path**
1. Run the relevant criterion bench (`policy_check`, `runtime_decision`,
   `audit_write`) before and after. The CI `bench-artifact` job publishes the
   numbers but does not block, so the comparison is yours to make.

## Local verification vs CI — they are not the same

`./scripts/verify.sh full` is the canonical local gate and runs: docs/version
checks, lint, the Rust workspace (excluding the PyO3 extension-module trap),
the Python binding via a throwaway venv, and the Node binding. That is most of
the signal, but it is deliberately **not** the whole CI bar.

| Check | `verify.sh full` (local) | CI |
| :--- | :---: | :---: |
| Rust workspace + lint + docs | ✅ | ✅ |
| Python / Node bindings | ✅ | ✅ |
| Per-OS sandbox integration (seccomp/Seatbelt/JobObject) | ❌ (needs that OS + feature flag) | ✅ (matrix runners) |
| Cross-language `parity-e2e` comparator | ❌ (needs all bindings built) | ✅ |
| `cargo-deny` / `cargo-audit` / SBOM / `npm audit` | ❌ | ✅ |
| Criterion benches | ❌ | ✅ (non-blocking) |

The consequence: a green `verify.sh full` is *necessary but not sufficient*.
The per-OS sandbox jobs and the parity comparator can only fail in CI, so do not
treat a clean local run as a guarantee that a sandbox or cross-language change is
done. The canonical, complete mandatory bar is the CI job list in
`CONTRIBUTING.md`.

Narrower local paths when you only changed one surface:

```bash
./scripts/verify.sh rust     # build + test workspace (excl. agent-guard-python), then nothing else
./scripts/verify.sh lint     # rustfmt --check + clippy -D warnings
./scripts/verify.sh python   # maturin develop + pytest in a tmp venv
./scripts/verify.sh node     # napi build + node tests + plugin tests
./scripts/verify.sh docs     # link checker + version consistency + content gates
```

To exercise a sandbox backend locally you must opt into its feature on its OS,
exactly as CI does:

```bash
cargo test -p agent-guard-sandbox --features seccomp --test seccomp_integration -- --nocapture   # Linux
cargo test -p agent-guard-sandbox --features macos-sandbox --test macos_integration -- --nocapture # macOS
```

## Definition of done

A behaviour change is done when:

- [ ] The new or changed behaviour is captured by a test that **fails without
      the change** and passes with it.
- [ ] If it closes a bypass, there is a permanent lock in
      `security_regression.rs` (or next to the code) citing the PR.
- [ ] If it touches a release invariant, the relevant `GATE` still passes and
      remains truthful.
- [ ] If it touches decision shape / codes / adapter modes, all three parity
      runners changed together and a scenario exercises it.
- [ ] If it touches a sandbox backend, the per-OS integration test was run on
      that OS with that feature.
- [ ] `./scripts/verify.sh full` is green locally, and you understand which CI
      jobs your change still has to clear that local cannot.

## Anti-patterns

- **A fix with no regression test.** The bypass will come back; nothing will
  notice. This is the single most important rule in the repo.
- **Mocking the policy engine or sandbox to assert on behaviour.** You end up
  testing the mock. The only sanctioned mock is a deliberately-failing
  dependency used to prove fail-closed reaction (GATE 1).
- **Asserting on audit log lines instead of the decision.** Logs are a forensic
  record, not the contract. Assert on the `GuardDecision` / `RuntimeOutcome`;
  treat logs as a separate, secondary assertion when the log content itself is
  the feature.
- **Weakening a gate to get CI green.** A red gate is information. Fix the code
  or change the gate as a reviewed decision — never as a quiet edit to make the
  number go green.
- **Landing a parity change in one language.** Green per-language tests with a
  divergent comparator is still a regression. The contract is the scenario set,
  not the individual binding.
- **Claiming isolation the platform does not provide.** The Linux baseline is a
  prototype/fallback wrapper today; describing it as production-grade syscall
  filtering fails both the docs linter and `GATE 2`.

## See also

- [Threat Model](threat-model.md) — what these tests are defending against.
- [Enforcement Layers (ADR)](enforcement-layers.md) — which layer is the real
  security boundary in each deployment shape.
- [Cross-Language Parity](cross-language-parity.md) · [Adapter Contract](adapter-contract.md)
- [`CONTRIBUTING.md`](../../CONTRIBUTING.md) — the operational verify + PR + green-CI loop.
</content>
</invoke>
