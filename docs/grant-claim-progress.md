# Permanent grant-claim repair checkpoint

Unreleased. The user authorized a separate prerequisite repair after PR #181
exposed repeated Windows grant claims. Branch `codex/grant-claim-fence` starts
from main `6751d9fb52c3eee14e939b1dc02376efd6fe571d`, **not** the deadline
branch. No deadline dependency/code is included. The original dirty checkout
and #181 are preserved. No merge, release, advisory change or automation is
authorized. [Plan/references](plans/2026-10-22-grant-claim-fence.md).

## Test-first and implementation evidence

- Actual native Windows red: #181 head `77864226237c440c65204a40e1ec1928e1d1d206`,
  run `39880569681`, job `120176690362` observed **16 successful claims for one
  ID** in the unchanged race test. This is not proof of 16 remote writes.
- Local test-first commit `894cf6f2b28121b3eb65482e31b532101ec110e8` contains
  only the new integration tests: **nine failed / one helper control passed**
  against unchanged production code. Some assertions specify the new marker
  lifecycle; they do not represent nine separate vulnerabilities.
- Exclusive permanent marker creation now precedes grant reads/archival. Every
  later failure retains it; legacy spent entries are never replaced, including
  dangling links. Marker-only state is recognized when recording a refusal.
  Grant JSON v2, receipt JSON v1 and public API signatures are unchanged.
- Final Broker suite: **84 passed / zero failed / one existing opt-in cost probe
  ignored**. The original 16-thread test is unchanged. New tests use eight
  actual processes with a ready/start gate and bounded waits; another process
  exits abruptly immediately after the actual production reservation without
  archival/unwinding, then a fresh caller is refused. No network/credential
  is involved in these new claim fixtures.
- Empty/partial markers, restored pending JSON, legacy/dangling archives,
  policy/expiry/corrupt validation failure, missing-source archival failure,
  successful archival followed by read failure, marker-only receipts and
  independent dotted IDs are covered. Unix markers/directories are private.
- First default-sandbox Broker run stopped at the existing loopback bind test
  with `Operation not permitted`. The unmodified suite passed after obtaining
  normal local-network permission; no test was skipped or weakened.
- A separate read-only design/final-source review found no blocking replay
  flaw in the protected local-store scope. Its additional read-failure case
  was added and passed. This is not independent runtime acceptance.

## Final local gates

- `./scripts/verify.sh full`: exit 0; **1,219 top-level Rust passes plus one
  nested child pass**, zero failures, three existing ignored summaries (the
  child-only probe is actually invoked by its parent). No new ignore.
- Python **108 passed / one optional framework skip**. Node native, types,
  adapter/framework checks pass; Actions **3/3**, plugin **14/14**.
- Strict workspace/all-features/all-target Clippy exits 0. Separate CLI **23/23**
  and authenticated owned-loopback Git **9/9** pass. Fresh Python/Node bindings
  match Rust on all **70** parity cases.
- Full's script tests **52/52**, Markdown/version/action-pin checks pass.
  Final checkpoint/docs/whitespace checks pass (90 Markdown files).
- No dependency, MSRV or version/tag/published-marker change.

Sanitized counts, hashes, reproducible test-first commit and the original
Windows job are retained in
[machine-readable evidence](security-evidence/2026-10-22/grant-claim-local.json).
Raw local logs under `/private/tmp/agent-guard-claim-*.log` are temporary.

## Remaining gate and operating limits

Exact new-head CI and PR status are tracked in the independent review PR;
do not make self-referential documentation commits solely to record its SHA.
Required macOS/Windows CI steps run the complete Broker and CLI tests; Linux
workspace, authenticated Git and fixed-container acceptance remain required.
No green checks from #181 substitute for this new head. #181 remains draft.

Use a protected broker-owned **local** store. Stop unpatched consumers before
upgrading; they ignore consumption markers. Never delete markers as stale locks
or restore only pending JSON for a retry. Backups must preserve consumption
state. Same-user store edits, old consumers, whole-store rollback, arbitrary
network filesystems and power-loss durability are not solved here. File sync
does not establish all of those guarantees. Windows ambient handles and
general shared-hard-link containment also remain open.
