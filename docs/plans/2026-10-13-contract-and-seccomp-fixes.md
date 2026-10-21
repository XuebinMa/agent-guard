# Attenu contract and seccomp maintenance plan

Date: 2026-10-13 (America/Los_Angeles).
Status: implementation authorized; validation and delivery are separate below.
Baseline: `a5140da0c1a8367d8879af48b3e51de8e83cfd06` (current main).
Branch: `codex/security-contracts-161`, in an independent local worktree.

## Scope and sources

This is bounded maintenance, not an expansion of the broker-first product.
Preserve the primary checkout's unrelated changes and all existing tags.
No upstream comments, issue closure, merge, release or advisory mutation is
authorized by this plan. Do not restart the cancelled patrol automation.

The Attenu verifier remains independently implemented from public contracts;
do not read, port or invoke the upstream reference implementations.

- [Upstream clarification](https://github.com/a2aproject/A2A/issues/1575#issuecomment-6131047511).
- [Pinned public contract](https://github.com/attenu-io/attenu-guard/blob/b62b3fa38feebc071ae384992e6c383c1e645ea7/tests/vectors/README.md#entry-fields).
- [Seccomp issue](https://github.com/XuebinMa/agent-guard/issues/161).
- [Rust pre-exec safety](https://doc.rust-lang.org/std/os/unix/process/trait.CommandExt.html#tymethod.pre_exec).
- [Testing strategy](../concepts/testing-strategy.md).

At inspection, the published bundle corpus is still v1.4, 20 cases, SHA-256
`58d3546d67b1bafd8c96e0a01ae80b4b722f46af3459f19ee2b0ef34893da00d`.
The promised v1.5 corpus is not an available acceptance result.

## Ordered work and acceptance

- [x] P0: inspect current main, dirty checkouts and explicit authorization;
  create an isolated implementation branch without overwriting other work.
- [x] P1: reproduce acceptance of a re-sealed v1 `outcome`, then make the event
  vocabulary chain-version-aware. Preserve valid v2 outcomes. Build truly
  legal v1 fixtures; removing outcomes requires sequence/hash/anchor repair.
  Keep exact reason/seq/node assertions and positive controls. Field sweeps
  must count the resulting fixtures, not retain the old 108/18 by weakening
  assertions. Add root/spawn wrong-wire-type regression controls without
  changing the already-strict authority parser.
- [x] P2: first reproduce malformed bundle-container acceptance/diagnostic
  gaps. Reject a non-object bundle, wrong-type entries/envelopes/anchor with
  chain-level `invalid_bundle` once per invalid member, without continuing
  semantic checks. Preserve documented absent/null semantics. Non-object
  entries retain chain-level `invalid_ledger_entry`, with an optional physical
  entry index for diagnostics; do not encode an index into the reason token.
- [x] P3: preserve the existing required-syscall fail-closed behavior. Prepare
  names/rules and allocating diagnostics before fork; the child installation
  path must avoid allocation/locking. Preserve detailed parent-side setup
  errors and distinguish installation errors from ordinary exec failures.
  Use existing Linux/seccomp mechanisms, not a new backend or daemon.
- [ ] P4: run targeted red/green tests, formatting, strict lint and full local
  gates against the final tree. Exercise real Linux/seccomp failure paths:
  unresolved required names, installation failure, no command side effects,
  correct error classification, positive controls and bounded concurrency.
  Native Linux CI must inspect the exact new head, including failure/skip
  conclusions; a portable helper test is not that acceptance.
- [ ] P5: when upstream actually publishes v1.5, pin its bytes/revision and run
  both the frozen baseline and repaired verifier. Report measured first-run
  and repaired results without inventing a score. Prepare any reply only
  after real results; posting remains separately authorized.

P4 local acceptance is complete: full macOS gate, strict all-target lint,
fresh Rust/Python/Node parity (70 cases), Linux VM seccomp unit (21), native
integration (14), no-feature unit (12) and strict native lint all passed.
The exact final-head hosted CI remains a separate review gate, to be recorded
in the PR rather than borrowing an older green result. P5 is conditional on
the still-unpublished corpus, not an implementation failure or a score.
See the [completion report](../security-review-2026-10-13.md) for red/green
evidence, compatibility costs and remaining limits.

## Newly discovered CI dependency gate

The first final-head run (`ea4b315`, `38514768978`) passed the dedicated
Linux seccomp tests but failed both dependency-security checks. The unchanged
baseline lockfile includes five advisories against `quinn-proto` 0.11.15;
the minimum patch covering all five is 0.11.18. Apply only that precise
lockfile update and its required random-number dependency closure, then
re-run local and hosted gates. Do not suppress advisories.

`cargo-deny` separately rejects unmaintained `unsafe-libyaml` 0.2.11 through
`serde_yaml`. RUSTSEC-2024-0449 has no patched version; a parser migration is
a distinct, security-sensitive policy compatibility change, not a lockfile
patch. Separate user authorization has been requested. Keep the existing
gate intact and this PR unmerged if that blocker remains; do not call it green.

## Environment and evidence rules

Integration checkpoint, 2026-10-21: the user authorized merge/issue closure
after new-head verification, and preparation (not publication) of a successor.
The separately reviewed parser migration #176 was merged as `ab55c5f` and is
normally merged into this branch without force-pushing. It removes the old
YAML chain, includes the minimum TLS security patches required by its CI, and
adds an exact Rust 1.89 policy-core job. The dependency-blocker notes above
describe the earlier heads, not the integrated graph. Preserve the original
Attenu/seccomp tests and the stronger fail-closed required-name behavior.

Before merging #175, inspect all 22 actual CI conclusions for the integrated
head and the Linux job's real 10 unit / 14 integration results with zero
ignored tests. Record the exact head/main push evidence in the PR and issue
rather than creating self-referential documentation commits. Only then close
#161 with a distinction between merged and released code. Future Attenu v1.5
interop results and unrelated platform limitations remain separate.

macOS can execute the offline Attenu verifier and portable seccomp-rule tests.
Linux-specific code is not validated by a successful macOS build. A Linux VM
can validate actual seccomp syscalls but does not establish the broker's native
host/container credential-isolation deployment claim. Record which was used.
The local Docker daemon was initially unavailable; this is not a passing test.

Use only synthetic JSON, local temporary files/repositories and bounded local
endpoints. No real credentials, third-party pushes or destructive command
execution. Keep negative regressions and existing fail-closed behavior.

Record each actual red/green command, exit status, exact tree/CI SHA, unrun
checks and remaining blockers in the completion evidence. Download counts do
not identify users or CI traffic, and a null CVE ID does not prove an accepted
allocation request. Do not expand this maintenance into promotion or adoption
tracking work.
