# 0.2.9 source preparation — completed

**Published and independently verified on 2026-10-22 UTC.** See the
[completed delivery record](release-029-delivery.md) and
[machine-readable evidence](security-evidence/2026-10-22/release-029.json).
The dated prepublication checkpoint below is retained as history: its 0.2.8
published-marker statements describe the preparation, not current registry
availability. Do not repeat the completed publication or move `v0.2.9`.

## Prepublication checkpoint

Checkpoint: 2026-10-22 (America/Los_Angeles), before publication.
Source candidate: **0.2.9**. Latest verified published version: **0.2.8**.

The initial authorization covered source preparation, not publication.
After #177 and #178 merged and their main CI passed, the user requested
"请完成上述3步": finish the release-closeout PR, complete formal 0.2.9 delivery
and independently verify the registry packages. This 2026-10-22 instruction
authorizes the new tag, normal protected registry workflow, GitHub Release
and post-verification published-marker update. It does not authorize moving
old tags, changing protection rules, new advisory scope, further upstream
comments or restarting the cancelled automation.

## Included fixes and provenance

- [#176](https://github.com/XuebinMa/agent-guard/pull/176), main merge
  `ab55c5fcbbbbca0d97e32a181bf06df4127ae6f5`: bounded policy parser migration,
  original-byte signature/reload contracts, 43 migration regressions, exact
  Rust 1.89 policy-core gate and minimal quinn/TLS dependency-security patches.
- [#175](https://github.com/XuebinMa/agent-guard/pull/175), main merge
  `bd4b1b6087dc97e5ca8f9e7bc34f4471092d3f78`: Attenu v1/container contracts,
  parent-side required-syscall/BPF preparation and fail-closed setup diagnostics.
  Its integrated head `9a8b39b28d7cb16452c2493c3ac6b6b98027622f` passed
  [22/22 CI jobs](https://github.com/XuebinMa/agent-guard/actions/runs/39648258931).
  The Linux log actually ran 10 native unit + 14 integration tests, zero
  failed/ignored. This does not prove arbitrary-kernel or credential isolation.
- The #175 merge passed main push CI
  [39688637686](https://github.com/XuebinMa/agent-guard/actions/runs/39688637686),
  22/22 SUCCESS, before #161 was closed with the native Linux evidence.
- [#177](https://github.com/XuebinMa/agent-guard/pull/177) prepared source
  0.2.9 and merged as `6af73d4a1e65895f57f09fb6436299577fee8409`.
  Its [head CI 39689096909](https://github.com/XuebinMa/agent-guard/actions/runs/39689096909)
  and [main CI 39694796986](https://github.com/XuebinMa/agent-guard/actions/runs/39694796986)
  each completed 22/22 SUCCESS.
- [#178](https://github.com/XuebinMa/agent-guard/pull/178) repairs corpus
  scoring of exact `reason`/`seq`/`node` triples without changing verifier
  decisions or removing `entry_index` diagnostics. It pins unmodified v1.5
  (29 cases, SHA-256 `1663000a67f38fcd54ff4856b39583b17ffec342f13f8d0921e2de0bc2bc25c5`).
  Its test-first commit reproduces the mismatch. The fix scores 29/29;
  the unchanged envelope corpus scores 19/19 and guard-verify passes 95 tests.
  Merge `b981614e0f4b0df81ae9231f16cfabd3a3e56a2a` has the same tree as
  tested head `2d3173e`. [Head CI 39696775285](https://github.com/XuebinMa/agent-guard/actions/runs/39696775285)
  and [main CI 39697676397](https://github.com/XuebinMa/agent-guard/actions/runs/39697676397)
  each completed 22/22 SUCCESS. This closeout must pass its own new CI;
  the previous green runs do not substitute for it.

The dated [contract/seccomp report](security-review-2026-10-13.md),
[parser profile](concepts/policy-yaml.md) and [CHANGELOG](../CHANGELOG.md)
retain conditions, compatibility costs and original red/green evidence.

## Source version is not registry availability

The atomic version tool updates ten workspace package versions, every exact
local dependency pin, both Python manifests, Node metadata/lock root, plugin
metadata and current-source documentation to 0.2.9. Published README/release
links and Python installation examples remain at 0.2.8 until independently
verified publication. No historical release heading or immutable tag moves.

Compatibility changes include source Rust 1.89, 1 MiB/finite policy budgets,
explicit quoting for numeric/boolean-looking string data and Linux 3.17+
with permitted `memfd_create` for seccomp BPF export. Do not rewrite user policy
files or relax gates to hide these costs.

## Preparation acceptance

- [x] All source markers and exact local pins are 0.2.9; published markers
  remain 0.2.8. The lock graph changes only workspace package versions in this
  preparation, not dependency versions or features.
- [x] #177's complete `./scripts/verify.sh full`, strict all-target lint,
  format/docs/action-pin checks and 70-scenario fresh-binding parity passed.
- [x] Isolated `cargo install --path ... --locked` for `guard-hook`,
  `agent-guard-cli` and `guard-verify`, matching 0.2.9 version output and
  installed-binary smoke checks with synthetic local fixtures.
- [x] Preparation PR's own exact-head 22-job CI, including actual Linux,
  Windows, macOS, bindings/frameworks, MSRV and dependency audit/deny.
- [x] #178 full verification passed: Rust 1,206 / zero failures / three
  existing ignores; Python 108 / one optional skip; Node checks passed and
  plugin 14/14 passed.
  The exact head passed 22/22 hosted jobs, including fresh-binding parity.
- [x] Documentation closeout's own verification and #179 head CI
  [39828133089](https://github.com/XuebinMa/agent-guard/actions/runs/39828133089)
  passed. Final main `8f29c88f40218ed289d115106bee00556a7a23e6` passed
  [39828921029](https://github.com/XuebinMa/agent-guard/actions/runs/39828921029),
  22/22 successful results. Attempt 2 reran only the stale-status documentation
  job; it retained the other 21 original successful executions.

Final preparation-head checks are recorded in its PR body, not another
self-head documentation/CI commit. A source install proves this checkout and
its workspace lock build/install together; it does **not** prove that a crate
tarball exists or that registry exact-version `--locked` installation works.
No real credentials, third-party push or user global Cargo installation is
used for these checks.

## Publication gates at preparation

These ordered gates are the original checklist, completed in the delivery
checkpoint below. They are not instructions to retag or republish 0.2.9.

1. Review/merge the verified closeout PR. Require successful push CI on
   that exact final main SHA and recheck it is still current main.
2. Create the matching new tag under the current user authorization. Respect release
   preflight, dependency gates and configured registry environment approvals.
   Never move `v0.2.7`/`v0.2.8` or reuse a previous tag/run.
3. Verify eight public Rust crates, all five Python wheel platforms and the
   npm plugin, hashes/contents and provenance. The Python/Node Cargo binding
   crates remain `publish = false`; the Node binding is not npm-published.
4. Independently download/install the **registry** exact-version packages
   with `--locked` in a new installation root and test actual decisions.
   Local `--path` installs are not a substitute. Do not remove exact pins or
   add temporary publication patches to work around missing new registry deps.
5. Only then update published markers and decide any warranted advisory or
   upstream communication. A merged fix is not a released fix.

Windows ambient handles, general shared-hard-link containment and Attenu
fractional TTL remain separate. The v1.5 corpus is now available and scored;
its twenty-nine rows still use only thirty of the thirty-nine published entry
fields, and finite agreement is not complete verifier coverage. These limits
are not converted into completed security claims by preparation or publication.

## Verified completion checkpoint — 2026-10-22 UTC

- [x] #179 merged normally to the exact successful main SHA above. The new
  annotated `v0.2.9` tag resolves to that commit and remains immutable.
- [x] [Release 39830348740](https://github.com/XuebinMa/agent-guard/actions/runs/39830348740)
  completed all ten jobs through the configured protected environment stages.
- [x] Independently downloaded and checked eight Rust crate archives, all five
  Python wheel platforms and the npm tarball, including contents, hashes and
  provenance. Separate npm 11.8.0 signature/attestation validation passed.
- [x] Three exact-version registry `--locked` CLI installations passed version
  checks and their scoped smokes. The actual macOS arm64 PyPI wheel passed
  import/decision checks; installed `guard-verify` scored 29/29 and 19/19.
  Other wheel platforms received content/hash checks, not installed execution.
- [x] GitHub Release became public at `2026-10-22T18:41:01Z`, non-draft and
  non-prerelease, after independent acceptance. The existing GHSA is unchanged.

The [delivery record](release-029-delivery.md) also records the temporary
archive-download acceptance-tool error and npm propagation wait without
concealing them as successful first attempts. Updating published markers and
retaining this evidence is a separate record-only PR, with its own CI; it does
not authorize another release, advisory change, upstream comment or automation.
