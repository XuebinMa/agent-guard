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
PR or review that added each regression, and `release_gate.rs` encodes five
invariants as `GATE 1..5`. This document makes that practice explicit so it is
followed by default rather than rediscovered per change.

A passing finite corpus does not prove a universal shell classifier or a
complete deployment boundary. Claims must identify the supported grammar,
backend/mode, principal and resource tested. The focused product acceptance is
broker-controlled remote mutation, not interpreting all arbitrary programs.

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
| **Sandbox per-OS** | `agent-guard-sandbox/tests/{seccomp,landlock,macos,windows_job}_integration.rs` | Documented OS resource restrictions on that host/feature; examine skips and positive controls | Any change to a sandbox backend (run on that OS, with that feature) |
| **Cross-language parity** | [`tests/cross-language-parity/`](../../tests/cross-language-parity/) | Rust ≡ Python ≡ Node for the same input | Any change to decision shape, codes, or adapter mode semantics |
| **Python binding / real frameworks** | `agent-guard-python/tests/*.py` (pytest), CI framework matrix | The PyO3 surface and adapters behave; supported-series and latest LangChain legs install the real framework | Changes to the Python API, stubs, or langchain/openai adapters |
| **Node binding** | `agent-guard-node/test*.js`, `packages/agent-guard-plugin/test/` (node:test) | The napi-rs surface and adapters behave | Changes to the Node API or adapters |
| **Bench (non-blocking)** | `*/benches/*.rs` (criterion) | Performance trend visibility | Performance-sensitive changes to the hot path |
| **Supply-chain & docs** | CI: `cargo-deny`, `cargo-audit`, SBOM, production `npm audit`; `scripts/check_docs.py` | Known dependency advisories/policy and detectable documentation drift; not absence of all vulnerabilities | Dependency changes; any docs edit |

Unit tests live next to the code; integration tests live in `tests/`. Security
regression cases go in the one suite named above so the attack surface is
auditable in a single file. These three rules come straight from
`CONTRIBUTING.md` and are not negotiable per-PR.

### The gate tests

[`release_gate.rs`](../../crates/agent-guard-sdk/tests/release_gate.rs) is the
spine of the existing SDK strategy. Today it locks five invariants:

- **GATE 1 — Fail-closed robustness.** A sandbox that errors on `execute()`
  must surface a hard `Err`, never a silent allow. Tested with a `FailingSandbox`
  mock that always errors — the one place a mock is correct, because the point
  is to prove the SDK's reaction to a failing dependency, not the dependency.
- **GATE 2 — Platform selection consistency.** `Guard::default_sandbox()` and
  the diagnosis agree on the selected backend, and the selection is *truthful*:
  when no real isolation is compiled in, the backend reports `"none"` rather
  than claiming syscall filtering it does not provide.
- **GATE 3 — Negative SDK execution path.** An attempted outside-workspace
  write must not succeed through `Guard::execute`. The current test accepts an
  SDK denial/error or a non-zero child exit, and returns early when no real
  backend is active. It therefore does **not** independently prove OS
  filesystem isolation: policy can stop the child, the target can already be
  unwritable, and a skipped backend is not evidence of containment.
- **GATE 4 — Receipt integrity.** When a signing key is supplied, the
  tool-call → execution → signed `ExecutionReceipt` chain verifies end to end.
  Receipts are opt-in and require an explicit key; they are not emitted
  automatically for every call. This test does not verify CLI `PushReceipt`
  signing or credential isolation.
- **GATE 5 — By-name backend truthfulness.** Unknown backend names fail;
  known unavailable backends resolve truthfully to none/fallback rather than
  reporting isolation they cannot provide. The seccomp feature enables native
  BPF on Linux; an unavailable/no-feature path must not pretend it did so.

An OS containment acceptance test must directly invoke the backend against a
temporary target that a positive unsandboxed control can change. Inspect both
exit status and the resulting file/ref. A noop backend, skipped runtime probe,
ordinary permission error or SDK rejection cannot substitute for that proof.
Linux seccomp is opt-in native BPF, but is path-agnostic and deliberately skips
filtering in `FullAccess`; test restricted-mode syscall promises rather than
assuming a workspace or credential boundary. Landlock is a separate
filesystem capability, not a credential-read or network policy.

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
3. Rebuild all bindings from the same tree and run the standalone comparator
   locally as well as in CI. Per-language tests alone do not establish parity;
   see the setup note below.

**Touching a sandbox backend**
1. Add or extend the per-OS integration test
   (`seccomp_integration.rs` / `landlock_integration.rs` / `macos_integration.rs` /
   `windows_job_integration.rs`). These only mean anything on the matching OS
   with the matching feature flag.
2. Re-check `GATE 2`, `GATE 3` and `GATE 5` assumptions: if you change which backend is
   selected or what it blocks, the gates must still pass and stay truthful.
3. State the real feature and mode. The default build uses noop; Linux seccomp
   with its feature enabled installs native BPF in restricted modes, while
   `FullAccess` skips filtering. Neither syscall filtering nor backend diagnosis
   establishes credential isolation. Do not call a fallback active isolation.

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
| Per-OS sandbox integration (seccomp/Landlock/Seatbelt/JobObject) | Matching-host tests may run; `full` does not run the cross-OS matrix | ✅ (matrix runners; inspect skips) |
| Cross-language `parity-e2e` comparator | ❌ in `full`; independently runnable after rebuilding all bindings | ✅ |
| Authenticated local Git/TLS host composition | ❌ in `full`; independently runnable with newly built CLI | ✅ (required dedicated job; not container isolation) |
| Broker-first native container acceptance | ❌ unless explicitly run on a supported native Linux Docker host | ✅ (required dedicated job; I1–I8 map combines real deployment with broker suites) |
| `cargo-deny` / `cargo-audit` / SBOM / `npm audit` | ❌ | ✅ |
| Criterion benches | ❌ | ✅ (non-blocking) |

The consequence: a green `verify.sh full` is *necessary but not sufficient*.
Per-OS tests on other operating systems need those hosts; the parity comparator
can run locally. Do not treat `full` as including every check or a clean local
run as proof of all sandbox/credential boundaries. The current CI matrix and
mandatory checks are documented in `CONTRIBUTING.md` and
[the workflow](../../.github/workflows/ci.yml).

For local parity, follow the workflow's `parity-e2e` setup: use a persistent
Python venv with `maturin develop --features extension-module`, rebuild the Node
addon, and invoke the comparator using that venv's Python from the repository
root:

```bash
.venv/bin/python tests/cross-language-parity/compare.py
```

The Rust runner is built/run by the comparator. `verify.sh python` removes its
throwaway venv afterward, so it does not leave the required Python module
available for this independent command. A comparator using stale installed
bindings is not verification of the current tree.

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
cargo test -p agent-guard-sandbox --features landlock --test landlock_integration -- --nocapture # Linux, compatible kernel
cargo test -p agent-guard-sandbox --features macos-sandbox --test macos_integration -- --nocapture # macOS
```

## Planned broker-first deployment acceptance

The [broker-first plan](../plans/broker-first-development-plan.md) defines a
first Linux container/host-broker profile. This document does **not establish
that its I1–I8 gates have passed**. Existing broker tests are necessary transaction
regressions, not a complete demonstration that every agent tool cannot reach
host credentials.

Acceptance uses temporary local repositories, public dummy authentication,
an authenticated loopback HTTPS endpoint and an independent remote-ref
observer. Pair a refused direct agent mutation with an approved broker mutation;
both paths failing proves neither isolation nor usability. Verify all runtime
paths, mounts, environment, authentication sockets, broker assets and approval
input—not just shell commands. A dedicated Linux container job must fail if its
required runtime/capabilities are missing instead of skipping or downgrading to
advisory/noop. Missing local prerequisites are recorded as **unrun**.

Current CLI confirmation is stdin-based, CLI push receipts are unsigned and
optional on disk, and `doctor` reports capabilities—not credential isolation or
an authenticated human approver. Strict profile acceptance must test the host
launch boundary separately. No new daemon, general interpreter or API-wide
transport restriction is needed to establish this first deployment contract.

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
      jobs it does not include. Run standalone parity for cross-language changes
      and inspect the exact head's required cross-platform CI conclusions.
- [ ] Deployment claims have their independent positive/negative controls;
      skipped/unavailable/noop paths are not recorded as isolation passing.

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
- **Claiming isolation the platform does not provide.** Native opt-in BPF is
  not a complete path/credential boundary; a default noop run, `FullAccess`
  bypass, skipped test or diagnosis report cannot prove enforced isolation.

## See also

- [Threat Model](threat-model.md) — what these tests are defending against.
- [Enforcement Layers (ADR)](enforcement-layers.md) — which layer is the real
  security boundary in each deployment shape.
- [Cross-Language Parity](cross-language-parity.md) · [Adapter Contract](adapter-contract.md)
- [`CONTRIBUTING.md`](../../CONTRIBUTING.md) — the operational verify + PR + green-CI loop.
