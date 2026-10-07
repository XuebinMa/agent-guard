# 0.2.8 successor delivery

## Direct decision and scope

On 2026-10-06 (Pacific time), the user answered:
"只能是自己先试用；停止旧发布、改发后继版本。"

This resolves the earlier release hold: stop the old 0.2.7 run, preserve its
tag, and deliver successor 0.2.8 through the existing protected process.
It does not invent a successful real pilot, authorize a third-party Git push,
broaden the existing GHSA, or close the Windows/shared-inode limitations.

The maintainer is the first user. The [self-pilot checklist](plans/broker-first-self-pilot.md)
tracks actual task/host/feedback separately from synthetic acceptance. A finite
maintenance release need not wait for P5 deployment/capacity feedback; release
claims must retain the fixed-profile and measurement limits.

## Confirmed old-run closure

At `2026-10-07T02:03:56Z`, GitHub reports
[run 37424509488](https://github.com/XuebinMa/agent-guard/actions/runs/37424509488)
as `completed / cancelled`. Rust publication, PyPI upload and npm publication
are each cancelled. Successful earlier wheel **builds** are not PyPI uploads.

`refs/tags/v0.2.7` still names annotated tag object
`ff2715f1c94daf7065f54eb4d6fc5e333ad9428a`, which resolves to original commit
`e1a0a0a5fd956186e67e9c235451cbfa2fb4b260`. It is not moved, overwritten,
deleted or reused. Do not rerun its publication. Historical registry observations
remain timestamped observations, not substitutes for fresh availability checks.

Fresh bounded public checks during this preparation returned version-not-found
HTTP 404 JSON for all eight Rust crates and PyPI at 0.2.7. npm returned HTTP 404
with the JSON string `"version not found: 0.2.7"`. The first generic classifier
refused to call that string-shaped response a verified absence; the actual npm
body/status were then inspected. No connection/error was counted as absence.

## New preparation

- [x] Use the existing atomic source-marker tool for 0.2.8. All ten workspace
  crates and language/plugin markers move together; published markers remain
  0.2.6 until availability is independently verified.
- [x] Roll the bounded follow-up into 0.2.8 notes and identify the 0.2.7 block
  as an unpublished source record. 0.2.8 includes that cumulative repair set.
- [x] Update the existing GHSA correction **draft** to 0.2.8 and its actual
  review status. Retain the original three-issue scope, affected `<= 0.2.6`,
  the five affected packages and absence of an invented CVE.
- [x] Freeze the new tree and pass full local verification, strict all-target
  lint and fresh Rust/Python/Node parity. Record actual exits/logs below.
- [ ] Normally commit/push to [PR #171](https://github.com/XuebinMa/agent-guard/pull/171)
  and require all checks on **that exact head**. Existing `02a7ef5` checks do
  not validate the version preparation. No force-push or protected-main bypass.
- [ ] Merge only the fully green head, then require final main SHA's push CI.
- [ ] Recheck main, tag that exact SHA as `v0.2.8`, and run release preflight.
  Respect environment reviews; never direct-publish around a protected gate.
- [ ] Verify eight Rust crates, five supported wheel platforms, npm provenance,
  and isolated exact-version `--locked` installations.
- [ ] Only after verification, correct the existing public GHSA using the
  [reviewed draft](ghsa-j64p-f672-v3jq-correction-draft.md), then update published
  markers through a normal reviewed PR and preserve final evidence.

## Verification and resume

The 0.2.8 local `verify.sh full` exited 0: 53 Rust result groups, 1,138 passed,
zero failed and three ignored summaries (the same two historical ignores plus
the opt-in performance probe already actually exercised six times previously).
Python passed 113/113 with real LangChain 1.6.6, no optional framework skip;
Node native/adapter/framework and plugin 14/14 passed. Strict all-target
workspace lint exited 0. The Python binding was rebuilt as 0.2.8 in the isolated
parity venv after the full build; the fresh comparator matched all 70 cases.
No required negative Shell strings were executed.

Logs: `/private/tmp/agent-guard-028-{full,strictlint,parity-build,parity}.log`.
Final recording-only edits require a fresh docs/whitespace check before commit.
These local results do not replace the new PR/main CI or establish publication.
Avoid a self-referential documentation/CI loop solely to record each new hash;
use PR/run artifacts for final exact-head evidence. Current source-marker status:
source 0.2.8, published 0.2.6.

Resume only unfinished tasks from this file and the current remote state.
Do not repeat unchanged successful gates, reissue old unanswered questions,
consume usage resets, purchase credits or overwrite either other checkout.
Keep the existing heartbeat active while authorized delivery or P5 remains
unfinished. Report progress/failure or genuinely missing authority, not a
simulated successful pilot or an unreleased patch as available.
