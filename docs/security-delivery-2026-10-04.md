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
- [x] Add a new fast-forward commit to existing PR #170. Preserve its current
  history and the exact verified working tree; do not force-push.
- [x] Check all CI job conclusions against the new head, including Linux
  seccomp/Landlock, macOS, Windows, bindings, framework matrices and parity.
  Fix actual failures and rerun the changed gates; old head checks do not count.
- [x] Prepare 0.2.7 source markers and release notes after the security CI passes.
  Version-only changes still require fresh CI on their own commit. Keep published
  installation markers at 0.2.6 until 0.2.7 is actually available.
- [ ] Correct GHSA-j64p-f672-v3jq's incomplete sed fix claim and affected range.
  Do not advertise 0.2.7 as an available patch before the registry release.
  The [correction draft](ghsa-j64p-f672-v3jq-correction-draft.md) includes separate
  pre-release and verified-release wording and the missing PyPI package.
- [ ] With explicit merge/publication authority, merge only a successful exact
  head; tag the tested main merge commit; verify all eight Rust crates, PyPI
  distribution and npm plugin before announcing availability.
- [ ] Record final release/advisory evidence and pause the heartbeat after the
  authorized delivery is complete.

## Current facts

- PR: [#170](https://github.com/XuebinMa/agent-guard/pull/170), still draft.
  Integration head: `38c95f6ffda83f9dabd7a6c89138aaa35da5e50f`, a direct child of
  the original `fd2c391`. Its original 19 green checks apply only to `fd2c391`.
- Latest published version: 0.2.6. Repair-release source preparation: 0.2.7.
- GHSA: [GHSA-j64p-f672-v3jq](https://github.com/XuebinMa/agent-guard/security/advisories/GHSA-j64p-f672-v3jq)
  is public/critical, presently says `<= 0.2.5` affected and 0.2.6 patched for
  validators, SDK, guard-hook and the npm plugin. The sed portion is incomplete
  in 0.2.6. The other two normalization/path fixes must not be described as
  regressed without evidence. The API currently reports no CVE ID for this GHSA.
  Add the published `agent-guard-python` PyPI package to the correction: its
  native wheel embeds the same SDK/validator path. Do not add the unpublished
  Node binding or indiscriminately flag all eight Rust crates.
- The review's 22 patched findings are not all part of that existing GHSA.
  Its correction must retain the existing scope rather than imply one advisory
  covers unrelated broker, binding or evidence-validation findings.
- R1 (Windows ambient handles) and R2 (shared hard-linked inodes) remain open.
  Passing CI for this patch does not close either finding.

## Latest delivery evidence

- Normal push updated #170 from `fd2c391` to `38c95f6`; no force-push, main change,
  merge, release or GHSA write has occurred in this delivery.
- Exact-head CI: [run 37262406637](https://github.com/XuebinMa/agent-guard/actions/runs/37262406637)
  (`pull_request`, `38c95f6`), completed/success. All **19 actual jobs** reported
  success, including workspace, Linux seccomp/Landlock, macOS, Windows, parity,
  lint, docs, cargo-audit/deny, SBOM, benchmark and both binding/framework matrices.
  This validates `38c95f6`; the forthcoming version-preparation commit still
  needs its own CI.
- Release preflight requires `tag commit == GITHUB_SHA == current origin/main`
  and a successful `ci.yml` push run for that same main SHA. A green PR run is
  necessary but insufficient for a registry publication.
- Atomic source bump completed: source 0.2.7, published markers still 0.2.6.
  Two negative marker tests failed because their mutations were hard-coded to
  0.2.6; the tests now derive actual fixture versions and assert that mutations
  occur. Full file-set rollback is also checked. All five marker tests pass.
  Release instructions now match the actual marker tool and protected-main gate.
- Version-preparation local gates passed: full verification exit 0 (Rust 1,069
  reported test executions, 0 failures, 2 ignored; Python 113 passed with real
  LangChain; Node/plugin tests); strict all-target lint and 30 cross-language
  parity scenarios; docs/version gates. Logs:
  `/tmp/agent-guard-release-027-preparation-full.log`,
  `/tmp/agent-guard-release-027-preparation-lint.log`,
  `/tmp/agent-guard-release-027-preparation-parity.log`.
- Plugin documentation now distinguishes install-time checks from the
  marketplace runtime wrapper and documents setup failure as aborting before
  settings writes. Source-version registry commands carry a pre-release warning.
  Private-config creation examples preserve existing files; Bash and Zsh local
  fixtures verified new mode 0600 and refusal to overwrite a public marker file.
- The version/release-preparation update follows `38c95f6` on the same PR. Its
  own exact-head CI must pass; read the current head/run from GitHub rather than
  treating `38c95f6`'s checks as proof for the new commit. Registry publication
  and public advisory mutation still await explicit authority/actual availability.
