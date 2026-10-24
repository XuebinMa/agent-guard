# 0.2.10 verified maintenance delivery

Published and independently accepted on **2026-10-24 UTC**. The
[GitHub Release](https://github.com/XuebinMa/agent-guard/releases/tag/v0.2.10)
became public at `2026-10-24T16:58:49Z`, non-draft and non-prerelease.
The [machine-readable evidence](security-evidence/2026-10-24/release-0210.json)
retains exact identities, methods, result files and log hashes.

## Authority and immutable source

The user explicitly authorized: "授权创建 v0.2.10 标签，并发布到 crates.io、PyPI 和 npm。"
This resolved the earlier action-review refusal, before which the attempted tag
operation did not execute. Fresh main/CI/tag/registry checks preceded the actual
authorized tag operation. Normal protected environments were used; no old tag,
protection, advisory, automation or upstream comment was changed.

Source preparation [PR #183](https://github.com/XuebinMa/agent-guard/pull/183),
head `9873b8c6b0ebd4f3d166d19a9449056c867a2cb1`, passed
[CI 40001015686](https://github.com/XuebinMa/agent-guard/actions/runs/40001015686)
with 22/22 completed/success jobs. Normal merge produced
`2da78b1d0b4ad3e62ebc02c09a6d0dd27f836181`; that exact main then passed its own
[push CI 40071399729](https://github.com/XuebinMa/agent-guard/actions/runs/40071399729),
22/22 completed/success, before tagging. Their source trees are identical.

Annotated `v0.2.10` tag object `1c1700a0829bb1a2a3e2d147d410d0738ee258b9`
resolves to that main commit. It is fixed and must not be moved or reused.
The existing v0.2.7, v0.2.8 and v0.2.9 tag objects remain unchanged.
[Release run 40112534342](https://github.com/XuebinMa/agent-guard/actions/runs/40112534342)
completed all ten jobs successfully: source guard, full/supply-chain preflight,
Rust publication, five wheel builds, PyPI upload and npm publication.
Environment approvals followed each preceding acceptance gate; neither rules
nor required checks were bypassed. A transient lag in API step-detail statuses
was resolved by inspecting the completed raw logs, not by skipping a check.

The final-main native Linux artifact names the exact release SHA, Broker
0.2.10, `accepted: true` and `cleanup_complete: true`. Independent download
and hash checks matched the artifact digest. Same-job Broker suites passed 96
tests with only the explicitly opt-in cost probe ignored; CLI suites passed
24 with none ignored. This proves the fixed synthetic Linux profile, not
arbitrary-host containment or a new human self-use result. Final-main SBOMs
for all ten workspace crates also matched their relevant dependency graphs.

## Published artifacts and actual installation

All eight non-yanked Rust crates were independently downloaded at exact
0.2.10: `agent-guard-core`, `agent-guard-validators`, `agent-guard-sandbox`,
`agent-guard-sdk`, `agent-guard-broker`, `agent-guard-cli`, `guard-hook` and
`guard-verify`. Acceptance checked registry SHA-256, clean source commit,
exact internal pins and packaged lockfiles. Critical claim/deadline/receipt
repair files were byte-compared against the immutable release tree.
SDK and binary locks that require Tokio contain 1.51.6; Broker/CLI/hook locks
contain process-wrap 10.0.1. The standalone Broker need not depend on Tokio;
SDK/verifier/Python graphs need not depend on process-wrap. Earlier TLS/QUIC
repairs and the bounded YAML parser remain in place; retired parsers are absent.

Five public `agent-guard-python` wheels cover Linux x86_64/aarch64, macOS
x86_64/arm64 and Windows amd64. Each actual download matched its registry
hash, size, abi3/platform metadata and wheel RECORD, and contains the wrappers
and native extension without dSYM/bytecode contamination. Their bytes match
the exact-run artifacts inspected before upload. Each embedded SBOM names
Tokio 1.51.6 and each build log actually compiles that version. Archive/log
checks are not installed execution on all five platforms.

All three Rust CLIs installed **from crates.io**, with exact `=0.2.10` and
`--locked`, into a new isolated Cargo home, target directory and install prefix.
They report 0.2.10. Installed hook decisions and verifier bundle **29/29** and
envelope **19/19** checks passed. The installed Broker CLI passed all **13/13**
authenticated loopback Git tests, including remote-state, one-use-grant and
uncertain-outcome checks. These use temporary owned fixtures and synthetic
credentials; no third-party push or real credential-isolation claim is implied.

The actual hash-pinned PyPI macOS arm64 wheel was installed in a fresh venv
and imported from site-packages under Python isolated mode, not from source.
Its five decision checks and two invalid-policy checks passed. Negative Shell
strings were decision inputs only, never executed. The other four published
wheel platforms were not installed or executed during local acceptance.

The dependency-free `agent-guard-plugin@0.2.10` tarball has exactly the intended
five files. Integrity, source bytes, preset and exact-version `--locked`/forced
revalidation installer contracts passed. In an isolated project, npm 11.8.0
`audit signatures` cryptographically verified **one registry signature and one
attestation**. The SLSA subject digest matches the actual tarball and its
statement binds this repository, release workflow, immutable tag/commit and
run 40112534342. Reading provenance fields alone was not counted as that proof.

The preflight product npm audit reported zero vulnerabilities and the published
plugin has no runtime dependencies. The separate Node development graph now
reports **eight advisory entries: 3 moderate, 4 high, 1 critical**. The earlier
preparation's count of six is preserved as historical evidence; dependencies
were not changed or advisories ignored to make this release pass. Zero product
dependencies is not a claim that build/test tooling has zero risk.

## Upgrade before reusing a grant store

1. Stop **all unpatched Broker consumers** before upgrading a shared store.
   Old binaries ignore the new `spent/claim-<id>.consumed` markers.
2. Keep permanent markers and archived JSON, including empty/partial markers.
   They mean consumed, not stale locks. Never remove them or restore pending
   JSON alone to retry. Failure or interruption requires a new approval ID.
   Whole-store rollback, writable stores/parents, arbitrary network filesystems
   and power-loss durability remain outside the guarantee.
3. Receipt schema v1 adds `attempt.outcome: indeterminate`. Rust exhaustive
   matches must add a branch; JSON readers must handle it or reject it, never
   convert it to success or definite refusal. Old pushed/refused bytes and
   signing preimages remain stable.
4. CLI exit **3** means the remote may already have changed. Preserve the
   exact URL/ref/old-new OIDs/grant ID and reconcile through a trusted read-only
   operator path. A timeout is not rollback. Never automatically retry a push;
   any later mutation needs a fresh preview and approval.
5. Existing downstream dependency lockfiles still need their own Tokio update.
   Publishing patched CLI locks does not rewrite consumers' application locks.

The [operations guide](guides/operations/broker-first-operations.md) and
[preparation history](release-0210-preparation.md) retain the complete limits.
Physical snapshot I/O and uninterruptible OS/filesystem/spawn work cannot be
forcibly cancelled; detached trusted helpers and supervisor death are not
contained. Output polling is not a strict disk quota. Advisory hooks and
unsigned receipts do not prove credential isolation. Windows ambient handles
and general shared-hard-link containment remain open. This release creates
no new representative-capacity or native Linux maintainer self-use result.

## Record-only follow-up

Published markers advance only after the verification above. This record PR
changes no production code, package manifest, lockfile or immutable tag and
does not publish again. Its own exact-head CI belongs in its PR body; no
self-referential documentation commit is needed. Merging that PR is a separate
review step. Existing GHSA/CVE scope and the cancelled automation are unchanged.
