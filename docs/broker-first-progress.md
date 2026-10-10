# Broker-first implementation progress

Baseline: `e1a0a0a5fd956186e67e9c235451cbfa2fb4b260`.

On 2026-10-06 the user authorized implementation of the accepted broker-first
development plan and continuation after normal usage-limit recovery. Work is in
this independent managed checkout; the original dirty checkout and the other
reviewer's patch are preserved. The historical release hold recorded below
was resolved by the direct successor decision; see the final delivery below.
`v0.2.7` must not move and its publication is cancelled.

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
  those are now locked by mutation fixtures. Real native Linux acceptance
  passed in CI below. Local Mac Docker was not started/installed; that local
  environment was not misreported as a native run.
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
  real native I1–I8 combined acceptance passed for `5f8e714` below.
- P5: bounded synthetic benchmark, 10 method tests and operator fault guide are
  implemented. Completed 1/8/32 MiB × 2 local runs independently checked refs
  and unsigned receipts. The method and machine are in the operations guide;
  whole-CLI timings alone are not copy/peak measurements. A test-only probe now
  measured the real copy functions separately on the same 1/8/32 MiB fixtures,
  plus exact held logical copy-data counts; six invocations passed with matching
  candidate/refs/unsigned receipts/spent grants. Details and raw JSON are in
  the operations guide. No true physical-peak, cold-cache or large-production
  claim. Real user
  feedback and representative deployment operating capacity remain pending.
- Release: this implementation record alone did not authorize publication;
  the subsequent direct decision and verified delivery are recorded below.

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

## Actual native milestone

Head `5f8e714933049352950648ae5e08c30b9ce8fa91` completed
[run 37524417236](https://github.com/XuebinMa/agent-guard/actions/runs/37524417236)
with **21/21 actual job conclusions success**. This includes fresh cross-platform
Rust, Python/Node/framework/parity, audit/deny and the required native Linux job.
The checked-out PR test merge was `427cf1d13efbe06bed85bb51901e3ec0bd6624d2`,
with parents baseline `e1a0a0a` and the exact PR head; main was not merged.

Downloaded [native evidence and complementary logs](security-evidence/2026-10-06/native-linux/README.md)
confirm `accepted: true`, complete cleanup, agent build/commit and verified TLS
401 connectivity, refused direct push, inaccessible named host authority,
strict pipe refusal, PTY cancellation/EOF and exact approved URL/OID/receipt/
spent grant agreement. The same job ran 69 broker and 23 CLI tests, zero failures
or ignores. P3/P4 now pass for this **fixed synthetic Linux deployment**;
arbitrary images/host services, real user approval costs and production capacity
are not covered. P5 remains partial, and publication remains held.

P5 follow-up red/green: two new method tests first failed for the absent probe
API, then all 10 passed. One ordinary held-file accounting test passed; the
performance test is explicitly opt-in and ran six times through the bounded
driver, not a hidden security-test skip. The first measurement invocation
rejected libtest's prefixed report marker; the emitter was corrected and the
next invocation completed. The successful report's source before/after state
was identical (dirty additions at `5f8e714`, not a pristine released tree).
No production copy/execution API was changed. A user question for the actual
Linux host/task/representative repository pilot is pending; do not invent it.

Frozen cost/evidence follow-up gates: `verify.sh full` exit 0, Rust summary
1,138 passed / zero failed / three ignored summaries (two pre-existing plus
the explicitly invoked opt-in cost probe), default Python 108 passed / one
optional-framework skip, Node/plugin 14/14. The separate real LangChain Python
leg passed 113/113 with no skip. Fresh binding parity matched all 70 cases;
strict all-target workspace Clippy passed. Final docs passed 52 script tests,
78 Markdown scans, workflow pins and source/published version consistency.
Logs are `/private/tmp/agent-guard-broker-first-cost-{full,strictlint,python-framework,parity,docs}.log`.
The measurement/docs additions require their own new PR-head CI; the earlier
`5f8e714` matrix is not reused as a green result for an unpushed commit.
Original CI log trailing blank lines failed staged `git diff --check`; the logs
are preserved byte-for-byte as Base64 with decoded hashes, like the original
partial-patch evidence. No whitespace gate was disabled or data discarded.

Windows ambient handles and shared-inode hard-link limitations remain open.

## Successor decision — 2026-10-06 (Pacific time)

The direct user instruction is: "只能是自己先试用；停止旧发布、改发后继版本。"
The first real pilot will therefore be the maintainer's own task, not invented
external feedback. Host/task/representative size and actual feedback are still
unrecorded; [the pilot checklist](plans/broker-first-self-pilot.md) preserves
these remaining acceptance items.

Old run `37424509488` is confirmed completed/cancelled: Rust publication,
PyPI upload and npm publication are cancelled. The `v0.2.7` tag is preserved.
Source markers move to `0.2.8`, published markers stay at `0.2.6`; only a new
exact-head verification may authorize delivery. Current successor steps and
evidence are tracked in [the 0.2.8 delivery checkpoint](release-028-delivery.md).
This resolves the earlier pending version choice, not P5 user/capacity feedback.

## Verified successor delivery — 2026-10-07 UTC

PR #171 was normally merged as `8cde12a509e8533bc6bbd1612b8012534c7d96a1`.
Both the final PR head and main push CI passed all 21 jobs; main's native
Linux artifact independently reports accepted/cleanup complete with broker
0.2.8. The new immutable tag points to that main commit, not a branch commit.
Release `37561573886` completed successfully through normal protected
environment approvals. Eight Rust crates, five wheel platforms and npm 0.2.8
were independently checked; isolated locked Rust installation and Python
decision checks passed, and npm signature/provenance verification passed.
The original three-issue GHSA correction is public, including the affected
Python package. Evidence is in [the delivery record](release-028-delivery.md).
P5 real maintainer feedback/capacity, Windows handles and general hard links
remain pending; publication does not close them.

## Maintainer macOS self-pilot — 2026-10-09 (Pacific time)

The maintainer personally cancelled then approved fresh previews in two local
CLI trials: a synthetic new-branch rehearsal and a small actual project
documentation commit with a normal fast-forward. Both reused the existing
authenticated HTTPS loopback fixture with synthetic credentials; no GitHub
push occurred. The helpers checked refs, unsigned receipts and consumed grants,
reported cleanup, and subsequent read-only checks confirmed disposable runs
were absent. The actual documentation commit remains retained locally.

Human feedback was “清楚知道，没觉得繁琐” for the synthetic trial and “仍然清楚、不繁琐”
for the project-task exercise. The [updated self-pilot record](plans/broker-first-self-pilot.md)
links verbatim sanitized summaries and separately records the second feedback.
This is bounded positive evidence for preview clarity and approval burden.
Task usefulness was not separately confirmed; native Linux maintainer use,
representative repository/host capacity and full physical peaks remain pending.
P5 stays partial. No additional release, advisory change or scheduled task is
authorized or created by recording these results.
