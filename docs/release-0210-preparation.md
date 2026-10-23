# 0.2.10 source preparation

Checkpoint: 2026-10-23 (America/Los_Angeles), **not published**.
Source candidate: **0.2.10**. Latest verified published version: **0.2.9**.

## Authority and baseline

The user authorized preparation of a separate release PR and its verification.
This does not authorize merging that PR, creating or moving tags, writing to
registries, publishing a GitHub Release, changing GHSA/CVE scope or restarting
the cancelled automation. Those delivery decisions remain separate.

The candidate starts at main
`f5c5f9ae017722bb68635d74dc2df19e9c597a8c`, after normal authorized merges
of [#182](https://github.com/XuebinMa/agent-guard/pull/182) and
[#181](https://github.com/XuebinMa/agent-guard/pull/181).
That baseline's [push CI](https://github.com/XuebinMa/agent-guard/actions/runs/39983757661)
completed 22/22 successful jobs. Its separately downloaded native Linux report
names that exact SHA and reports acceptance and cleanup complete for the fixed
synthetic profile. These are baseline results, not this preparation head's CI.
The final PR body will record this candidate's exact head and fresh CI evidence;
do not create another commit solely to record its own resulting SHA.

## Included repairs

- **One-use grant claims:** permanent exclusive consumption markers prevent a
  second patched process from claiming the same ID. A native Windows regression
  observed 16 concurrent successful claims before the repair, not 16 remote
  writes. Failure and interruption do not revive the authorization. Windows
  CLI approval-ledger access also retains the read permission required by its
  existing lock; it remains an unauthenticated advisory ledger.
- **Finite Git budgets and truthful outcomes:** one monotonic budget covers
  each preview or execution, default 300 seconds, configurable from 1 to 3600.
  Human confirmation is outside those budgets. Managed subprocess cleanup and
  capped output capture avoid unbounded ordinary child waits. A lost push
  acknowledgement produces `indeterminate`, not a false definite refusal.
- **Locked dependency repair:** Tokio 1.51.6 addresses RUSTSEC-2026-0386 without
  changing the compatible manifest range or Rust 1.89 MSRV. Existing downstream
  lockfiles still need their own update; no advisory is ignored.
- **Test synchronization:** Python lifecycle tests wait within a finite budget
  for asynchronously queued audit records. This changes no production audit
  queue, drop policy, API or durability guarantee.

The [CHANGELOG](../CHANGELOG.md), [deadline checkpoint](broker-git-deadline-progress.md)
and [repair evidence](security-evidence/2026-10-23/merge-blocker-repairs-local.json)
retain earlier red/green controls and actual failed CI history. This preparation
changes versions and documentation, not those production repairs or tests.

## Upgrade and reader compatibility

Read the [operations and recovery guide](guides/operations/broker-first-operations.md)
before using a patched Broker with an existing grant store.

1. Stop **all old Broker consumers** before sharing that store with the new
   version. Old binaries ignore the new `spent/claim-<id>.consumed` markers.
2. Preserve both permanent markers and archived grant JSON. Empty or partial
   markers already mean consumed; they are not stale locks. Do not delete them,
   restore only pending JSON, or replay a grant after failure. A fresh approval
   uses a new ID. Whole-store rollback, writable stores/parents, arbitrary
   network filesystems and power-loss durability are outside the guarantee.
3. Broker receipt schema v1 gains `attempt.outcome: indeterminate`. Existing
   pushed/refused bytes and signing preimages stay stable, but Rust exhaustive
   matches must add a branch; JSON consumers must handle the new value or reject
   it explicitly. Never map an unknown result to success or definite refusal.
4. CLI exit **3** means the remote may already have changed. Preserve the exact
   URL, ref, old/new OIDs and grant ID; reconcile through a trusted read-only
   operator path. Do not automatically push again or assume timeout rolled back
   the update. Any later mutation needs a fresh preview and approval.

Physical snapshot I/O and uninterruptible OS/filesystem/spawn work are not
forcibly cancelled. Cleanup needs a live supervisor and does not contain
deliberately detached malicious trusted helpers. Output polling is not a strict
disk quota. Optional unsigned CLI receipts do not prove credential isolation.
Windows ambient handles and general shared-hard-link containment remain open;
the fixed Linux profile is not a guarantee for arbitrary hosts or images.

## Preparation acceptance

- [x] Atomic source bump to 0.2.10 across ten Cargo packages, exact local pins,
  both Python manifests, Node/plugin metadata and current-source documentation.
- [x] Published markers and installation/release links remain 0.2.9. No old tag,
  historical release note, advisory or unrelated dependency is changed.
- [x] Complete local verification: 1,235 top-level Rust passes plus one nested
  child pass, zero failures and three existing ignored summaries; Python
  112 passed / one optional framework skip, Node checks, plugin 14/14,
  scripts 52 and 93-document gate. Strict all-target lint, fresh-binding
  Rust/Python/Node parity 70/70, cargo-deny and cargo-audit pass.
- [x] Three isolated debug source `--locked --offline` CLI installations report
  0.2.10; safe hook allow/ask/deny, verifier 29/29 and 19/19, and installed-CLI
  authenticated loopback Git 13/13 pass. Local macOS arm64 wheel wrappers,
  native module, metadata, RECORD and exclusions checked; its isolated installed
  70-scenario output matches the rebuilt binding. Dependency-free plugin pack
  contains only the five intended files and the byte-identical preset.
  These are not registry-install or five-platform release acceptance.
- [ ] Exact preparation-head complete cross-platform CI and native evidence.

The [local preparation evidence](security-evidence/2026-10-23/release-0210-preparation-local.json)
records methods, environment, hashes and coverage. This checkbox is the
pre-commit checkpoint; the PR body records final exact-head CI without another
self-referential documentation commit. Full's existing child-only environment
probe is invoked by its parent; the other two ignored summaries are opt-in cost
probes. No required security regression is newly skipped. The Node development
graph's six advisory entries remain; the product dependency audit is separate.

The preparation's Cargo.lock diff must change only the ten workspace package
versions; the baseline's Tokio 1.51.6 and other dependency versions/edges remain.
No new production behavior needs a new regression in this version-only PR;
the existing repairs' negative controls must remain enabled and pass.

## Separate delivery gates — not authorized here

1. Obtain authority for normal merge/publication. Require the verified head,
   then the exact resulting current-main push CI, before any new tag.
2. Respect source/preflight checks and protected registry environments. Preserve
   all existing tags; never republish or reuse an old version.
3. Independently verify eight Rust crates, five Python wheel platforms and the
   npm plugin, including hashes, source/lock contents and npm provenance. The
   Python/Node Cargo binding crates remain non-published; no new npm binding is
   introduced. The wheel workflow does not explicitly pass `--locked`, so green
   CI alone cannot establish the eventual wheel's dependency contents.
4. Install exact registry versions with `--locked` into an isolated prefix and
   run installed-binary checks. Source `--path` installs do not prove this.
5. Only after successful publication/acceptance update published markers. Assess
   any warranted advisory separately, with demonstrated affected versions;
   do not alter the old GHSA scope or invent a CVE as part of preparation.
