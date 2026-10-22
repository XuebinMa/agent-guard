# 0.2.9 verified maintenance delivery

Published and independently verified on **2026-10-22 UTC**. The
[GitHub Release](https://github.com/XuebinMa/agent-guard/releases/tag/v0.2.9)
became public at `2026-10-22T18:41:01Z`, non-draft and non-prerelease.
Artifact hashes, exact package versions, CI and installation observations are
retained in the [machine-readable evidence](security-evidence/2026-10-22/release-029.json).

## Authority and scope

After the verified fixes and source preparation merged, the user requested
"请完成上述3步": finish the closeout PR, deliver 0.2.9 through the protected
workflow, and independently verify the registry packages. This authorized
normal publication and the post-verification published-marker update, not a
protection bypass, old-tag movement, new advisory scope or another upstream
comment. The cancelled automation is not restarted.

This maintenance release includes #175's Attenu v1/container contracts and
parent-side seccomp preparation/diagnostics, #176's bounded policy-YAML parser
migration and dependency-security patches, #177's source preparation, and
#178's published-triple corpus scoring with the unmodified v1.5 fixture.
The [preparation checkpoint](release-029-preparation.md),
[CHANGELOG](../CHANGELOG.md) and [policy profile](concepts/policy-yaml.md)
retain the original evidence and compatibility boundaries.

## Immutable source and completed gates

Closeout [PR #179](https://github.com/XuebinMa/agent-guard/pull/179), head
`6d7d3f9`, passed [CI 39828133089](https://github.com/XuebinMa/agent-guard/actions/runs/39828133089),
22/22 successful jobs. Its normal merge produced
`8f29c88f40218ed289d115106bee00556a7a23e6`.
That exact current main passed [push CI 39828921029](https://github.com/XuebinMa/agent-guard/actions/runs/39828921029),
22/22 completed/success results, before tagging.

The main run's second attempt reran **only Documentation Check** because its
original aggregate UI/API status remained in progress after the steps had
completed successfully. The other 21 successful executions were retained:
their original start/end timestamps are unchanged. This is not a claim that
the entire matrix executed a second time.

The annotated `v0.2.9` tag object
`f454ebdaa03a6ba75dd6470bdedb29d94348be20` resolves to that main commit.
The tag is fixed; do not move, overwrite or reuse it. Existing `v0.2.7` and
`v0.2.8` are unchanged. [Release run 39830348740](https://github.com/XuebinMa/agent-guard/actions/runs/39830348740)
completed all ten jobs successfully: exact-source guard, full/supply-chain
preflight, ordered Rust publication, five wheel builds, PyPI upload and npm
publication. Configured environment reviews were respected; no registry write
was routed around a protected stage.

Independent inspection of the main seccomp logs found 10 native unit and 14
integration tests passing, zero failures or ignored tests. The unit command
explicitly selected the native tests, with 11 other tests filtered out; this
does not mean every sandbox unit test was executed by that command.
Downloaded native artifact `12447457758` reports the exact release SHA,
broker 0.2.9, `accepted: true` and `cleanup_complete: true`. Its accompanying
broker suites passed 70 tests with only the explicitly opt-in cost probe
ignored; CLI suites passed 23 with none ignored. This is the fixed synthetic
native Linux profile, not arbitrary-host containment or human approval proof.

## Registry artifacts and installed acceptance

Independent downloads verified all eight exact, non-yanked Rust crates:
`agent-guard-core`, `agent-guard-validators`, `agent-guard-sandbox`,
`agent-guard-sdk`, `agent-guard-broker`, `agent-guard-cli`, `guard-hook` and
`guard-verify`, each at 0.2.9. Checks covered archive SHA-256, source commit,
exact internal dependency pins, packaged lockfiles and relevant patched
dependency versions. The published `guard-verify` archive contains the pinned
bundle v1.5 fixture. No old dependency pin was loosened to obtain an install.

The five public `agent-guard-python` wheels cover Linux x86_64/aarch64,
macOS x86_64/arm64 and Windows amd64. Downloads matched registry hashes,
sizes, CPython >=3.10 abi3/platform metadata and wheel RECORD entries, and
included Python wrappers plus the native extension without dSYM/bytecode
contamination. Archive/content checks are not five-platform execution tests.

All three Rust CLIs installed from crates.io with exact 0.2.9 versions and
`--locked` into an isolated prefix; their version outputs match. Installed
`guard-hook` and the actual hash-pinned macOS arm64 PyPI wheel returned the
expected allow/ask/deny decisions on safe fixture inputs. The wheel was imported
from a fresh venv's site-packages, not from the source checkout. Additional
wheel policy negatives passed. Installed `guard-verify` scored bundle v1.5
**29/29** and unchanged envelope v1.2 **19/19**; the installed broker CLI's
version/help contract passed. These smokes do not claim a new real remote push
through the installed broker or actual installed-wheel execution on the other
four platforms. Negative Shell strings were decision inputs only, never run.

The dependency-free `agent-guard-plugin@0.2.9` tarball's integrity and contents
were checked, including its exact-version, `--locked` installer contract.
`npm audit signatures` with npm 11.8.0 independently verified one registry
signature and one attestation. The SLSA v1 subject digest matches the tarball;
the statement binds this repository, `.github/workflows/release.yml`,
`refs/tags/v0.2.9`, the exact source commit and release run 39830348740.
Reading statement fields alone was not counted as cryptographic validation.

## Acceptance-tool correction and registry propagation

The first archive-verification invocation treated a crates.io API download
response containing JSON as if it were a gzip crate archive and failed its
checksum check. The temporary acceptance tool was corrected to download from
the official static crate URL while retaining the registry checksum check;
the complete verification then passed. This was an acceptance-tool error,
not evidence of a corrupt release. No artifact, dependency pin or checksum
expectation was changed, and no security gate was weakened.

npm briefly returned a definitive version-not-found response after its
publication job succeeded. Normal waiting allowed registry propagation, then
the exact version became available and verified. It was not republished to
work around the delay. Network errors were not counted as version absence.

## Compatibility and limits retained

- Source MSRV is Rust 1.89. The exact-minimum CI gate tests the policy core;
  current-stable workspace and platform jobs remain separate evidence.
- Policy YAML allows one document, at most 1 MiB and finite structural/alias
  budgets. Duplicate keys, merges and unsupported tags are rejected. Quote
  numeric/boolean-looking string values; implicit scalar-to-string coercion is
  not preserved. Boolean fields accept case-insensitive `true`/`false`, not
  `yes`/`no`/`on`/`off` or quoted booleans. See the policy profile for the
  complete migration contract.
- Restricted Linux/seccomp preparation requires Linux 3.17+ and permitted
  `memfd_create`; unavailable prerequisites fail closed. FullAccess deliberately
  skips syscall filtering. Syscall filtering alone is not credential isolation.
- The hook remains decision-only, advisory and fail-open. Credential isolation
  depends on the deployment; ordinary unsigned receipts do not prove it.
- Windows ambient handles, general shared-hard-link containment and Attenu
  fractional TTL remain open. The 29 bundle rows use only 30 of the 39 published
  entry fields; finite conformance is not a complete verifier guarantee.
- Native Linux maintainer use and representative capacity/full physical-peak
  evidence are not created by this maintenance publication.

The existing GHSA was not changed or expanded and no CVE identifier is invented
by this release. Published markers advance only in the subsequent record-only
PR after the completed verification above. That PR needs its own exact-head
and final-main CI, recorded in its PR body; it does not create another release
or move the immutable release tag.
