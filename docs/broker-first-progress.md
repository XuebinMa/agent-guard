# Broker-first implementation progress

Baseline: `e1a0a0a5fd956186e67e9c235451cbfa2fb4b260`.

On 2026-10-06 the user authorized implementation of the accepted broker-first
development plan and continuation after normal usage-limit recovery. Work is in
this independent managed checkout; the original dirty checkout and the other
reviewer's patch are preserved. Version/publication choices remain separate;
`v0.2.7` must not move and its release remains held.

- P1 S1–S3: implemented locally. Original partial patch, five diagnostics and
  historical logs are preserved under `docs/security-evidence/2026-10-06/`.
  New parser tests failed 4/5 on baseline; SDK sec65/66/68 and real hook decisions
  also failed before the repair. Nested substitution sec67 was already refused
  by the SDK: its parser fix is defense in depth, not an execution bypass claim.
  Targeted green: validators 319 unit + 5 new integration + 3 corpus; SDK 79/79;
  hook 13/13. Shared parity comparator passed all 70 cases on real freshly built
  Rust/Python/Node bindings.
  No negative Shell strings are executed. Local full/strict lint passed below;
  first exact-head CI passed all 20 jobs at `c1f9ee1` (run `37523251183`). Later
  additions require their own head; this is not native P4 evidence.
- P2 C1–C3: document corrections implemented, including README/ROADMAP and
  durable scope/plan entry links. Recheck docs after the remaining additions.
- P3 D1–D3: fixed native Linux Docker launcher implemented; 20 configuration,
  permission, terminal and local-data tests passed. Independent source review
  found missing inspect checks for Docker protection lists/restart/logging;
  those are now locked by mutation fixtures. No real container run yet. Local
  Docker client exists, but daemon is not running; it was not started/installed.
- P4: six localhost TLS/authenticated Git composition tests passed on the
  rebuilt managed-checkout CLI. They verify exact ref/receipt, pre-connection
  scope refusal, cancel/EOF, reachable unauthenticated refusal, bounded TLS
  cleanup, and observer-error semantics. These are host composition, not
  container-isolation proof. Three additional bind checks passed (9/9 suite)
  for the opt-in verified private Docker bridge extension; they use mocked
  interface metadata, not native containment. Native driver/image and dedicated
  required Ubuntu job are implemented; 10 driver unit tests passed. Actual
  Docker has not run locally. Five new actual execution-API lifecycle tests
  pass without remote contact for missing/expired/inconsistent/consumed records,
  plus valid local-file push/replay. They complement the existing invariants;
  real native I1–I8 combined acceptance remains pending the new CI head.
- P5: bounded synthetic benchmark, 8 method tests and operator fault guide are
  implemented. Completed 1/8/32 MiB × 2 local runs independently checked refs
  and unsigned receipts. The method and machine are in the operations guide;
  no pure-copy, true-peak, cold-cache or large-production claim. Real user
  feedback and representative deployment operating capacity remain pending.
- Release: held; no registry/advisory writes authorized by this record.

## Verification checkpoint

First full invocation stopped at the docs/unit leg: the newly added deployment
test was discovered before its implementation file was written. This is an
in-progress tree, not a successful gate. Log:
`/private/tmp/agent-guard-broker-first-full.log` (exit 1). The test was not skipped.
After P3 freeze, the new full run completed with exit 0:
`/private/tmp/agent-guard-broker-first-final-full.log`. Rust result summaries
total 1,132 passed / 0 failed / 2 ignored; Python with real `langchain-core`
113 passed; Node native/adapter/framework and plugin 14/14 passed. Docs/script
unit leg ran 42 tests; subsequent Python/docs/CI additions need their own check.

Strict all-target Clippy against the frozen Rust tree also exited 0:
`/private/tmp/agent-guard-broker-first-strictlint.log`. Fresh CLI TLS suite 6/6:
`/private/tmp/agent-guard-broker-first-auth.log` (exit 0). Independent parity:
`/private/tmp/agent-guard-broker-first-parity.log` (70/70 identical, success).
Python-specific all-target lint:
`/private/tmp/agent-guard-broker-first-python-strictlint.log` (exit 0).
Baseline/new-tree results must not be mixed. Initial commit `c1f9ee1` is pushed
as [draft PR #171](https://github.com/XuebinMa/agent-guard/pull/171). Its
[CI run](https://github.com/XuebinMa/agent-guard/actions/runs/37523251183) has
20/20 completed/success conclusions. No merge, tag or publication occurred.

The fixture-only bridge extension was introduced after the full Rust run. Its
new unit tests first failed for the absent API (not a pre-existing vulnerability),
then all nine host/metadata tests passed:
`/private/tmp/agent-guard-broker-first-auth-final.log` (exit 0). No production
Rust behavior changed after the successful full/parity/strict-lint results.
Broker ordering comments were corrected and five lifecycle regressions added;
their targeted test/lint exited 0. New native/P5 scripts still need final docs,
driver and exact new-head CI gates. The initial green run must not be reused.

Final pre-push checks for the native/P5 additions: docs/version/workflow pins
exit 0 (50 script tests, 77 scanned Markdown files), driver 10/10, broker
authorization 5/5, broker all-target Clippy and workspace format check exit 0.
These local driver tests do not start Docker. The new CI job must actually
build the pinned synthetic image and execute the fixed deployment workflow.

Windows ambient handles and shared-inode hard-link limitations remain open.
