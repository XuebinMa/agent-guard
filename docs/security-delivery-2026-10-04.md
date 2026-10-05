# Security patch delivery — 2026-10-04

This continues the [defensive review](security-review-2026-10-04.md). The review's
verification records are historical snapshots; this file tracks subsequent
delivery separately so old green checks cannot authorize a new commit.

## Authorized scope and resume rules

The user authorized incorporating the local patches into a PR, running
cross-platform CI on the new commit, and preparing the repair release and GHSA
correction. Formal merge/publication authority has been asked separately; until
that answer arrives, prepare the release but do not merge or publish packages.

The existing `agent-guard` thread heartbeat is active on its two-hour cadence.
After normal quota recovery, resume only unfinished work from this file and
current GitHub state. Do not consume a usage reset or buy credits. Local scheduled
work requires the computer and desktop app to remain running. Do not replace
user changes or repeat unchanged successful gates.

## Delivery plan

- [x] Preserve the original 15 fixes and integrate #170, including additional
  regressions and its final `find -exec` positive-control correction.
- [x] Verify the frozen code locally: full gate exit 0; Rust 1,069 reported test
  executions; Python 113 passed with both real LangChain 1.6.6 and 0.3.86; strict
  all-target lint; 30 Rust/Python/Node parity scenarios; documentation gates.
- [x] Confirm main remains `4dc4bb3151c483acdda945466cdb478d667d94c1` and #170's
  existing head is `fd2c391823c683c6f57cfc43804914c3a090acc7`.
- [ ] Add a new fast-forward commit to existing PR #170. Preserve its current
  history and the exact verified working tree; do not force-push.
- [ ] Check all CI job conclusions against the new head, including Linux
  seccomp/Landlock, macOS, Windows, bindings, framework matrices and parity.
  Fix actual failures and rerun the changed gates; old head checks do not count.
- [ ] Prepare 0.2.7 source markers and release notes after the security CI passes.
  Version-only changes still require fresh CI on their own commit. Keep published
  installation markers at 0.2.6 until 0.2.7 is actually available.
- [ ] Correct GHSA-j64p-f672-v3jq's incomplete sed fix claim and affected range.
  Do not advertise 0.2.7 as an available patch before the registry release.
- [ ] With explicit merge/publication authority, merge only a successful exact
  head; tag the tested main merge commit; verify all eight Rust crates, PyPI
  distribution and npm plugin before announcing availability.
- [ ] Record final release/advisory evidence and pause the heartbeat after the
  authorized delivery is complete.

## Current facts

- PR: [#170](https://github.com/XuebinMa/agent-guard/pull/170), still draft before
  this delivery. Its original 19 green checks apply only to `fd2c391`.
- Source and latest published version: 0.2.6. Planned repair release: 0.2.7.
- GHSA: [GHSA-j64p-f672-v3jq](https://github.com/XuebinMa/agent-guard/security/advisories/GHSA-j64p-f672-v3jq)
  is public/critical, presently says `<= 0.2.5` affected and 0.2.6 patched for
  validators, SDK, guard-hook and the npm plugin. The sed portion is incomplete
  in 0.2.6. The other two normalization/path fixes must not be described as
  regressed without evidence. The API currently reports no CVE ID for this GHSA.
- The review's 22 patched findings are not all part of that existing GHSA.
  Its correction must retain the existing scope rather than imply one advisory
  covers unrelated broker, binding or evidence-validation findings.
- R1 (Windows ambient handles) and R2 (shared hard-linked inodes) remain open.
  Passing CI for this patch does not close either finding.

## Latest delivery evidence

Awaiting the new PR commit and its cross-platform CI. No merge, release or GHSA
write has occurred in this delivery yet.
