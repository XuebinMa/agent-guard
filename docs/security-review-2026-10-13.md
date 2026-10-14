# Attenu contract and seccomp maintenance, 2026-10-13

Baseline: `a5140da0c1a8367d8879af48b3e51de8e83cfd06` (main, including
test-only PR #174). The red-test checkpoint is `bff29f3`. The implementation
is isolated on `codex/security-contracts-161`; no primary-checkout changes,
tags, release markers or dependencies were changed. Exact final-head hosted
CI belongs in the review PR, separately from the local results below.

The [plan](plans/2026-10-13-contract-and-seccomp-fixes.md) scopes this as
bounded maintenance, not a new verifier platform or sandbox backend. No
upstream comment, issue closure, merge, release or advisory update was made.
All fixtures use synthetic JSON, temporary files and local processes. No
credentials, third-party writes or attack commands were used.

## Findings, patches and regression locks

### Attenu v1 accepted a v2-only event

**Severity: Medium for consumers relying on the verifier's schema acceptance.**
A correctly re-sealed v1 ledger could contain `outcome` after removal of the
twelve v2-only fields. The shared eight-event table accepted the name without
checking the chain version. This is incorrect evidence acceptance; it does
not itself grant broker authorization or execute a command.

- Path: [`schema.rs`](../crates/guard-verify/src/attenu/schema.rs), through both
  public bundle verifier entry points.
- Conditions: a producer supplies a v1 ledger and can produce an otherwise
  acceptable chain/anchor, or the consumer uses the optional-anchor API.
- Patch: retain the closed eight-name vocabulary but exclude `outcome` on v1.
- Regression: `a_v1_outcome_with_no_v2_fields_is_not_a_verified_no_op` failed
  before the production fix with "a v1-only outcome was accepted" (exit 101).
  It now reports exactly `unknown_ledger_event` at seq 5 / `vectors:n1`.
- Positive controls: legal v1 has seven entries after removing outcomes and
  repairing sequence/hash/anchor; v2 retains both outcomes and binding checks.
  Exact field sweeps now cover 84 v2-field mutations (12 x 7) and 16 unknown
  field mutations (7 + 9). The former 108/18 counts described invalid v1
  fixtures and are not retained as an inflated coverage claim.
- Existing root/spawn wire-type rejection is unchanged. New tests lock
  string `ttl` and object `scopes`; the authority parser was not rewritten.

### Malformed bundle containers were projected into absent containers

**Severity: Medium for offline evidence acceptance and diagnostic consumers.**
Wrong-type `envelopes` could be treated as absent while an otherwise valid
ledger was accepted. Other malformed containers produced misleading downstream
reasons instead of the contract's `invalid_bundle` result.

- Paths: [`mod.rs`](../crates/guard-verify/src/attenu/mod.rs),
  [`version.rs`](../crates/guard-verify/src/attenu/version.rs),
  [`structure.rs`](../crates/guard-verify/src/attenu/structure.rs),
  [`envelope.rs`](../crates/guard-verify/src/attenu/envelope.rs).
- Patch: validate the bundle and container types before any semantic pass;
  return one chain-level `invalid_bundle` per malformed member, zero counters
  and `not run` binding. Preserve missing/null semantics, including consistent
  null-anchor-as-absence handling. A required signer still rejects an absent
  anchor through the existing integrity check.
- Diagnostics: non-object entries retain `invalid_ledger_entry` with null
  seq/node and gain an optional zero-based `entry_index`. Ordinary failure
  JSON is unchanged; old JSON lacking this new member still deserializes.
- Regression: the initial eight shape tests had 3 passes / 5 failures on the
  unfixed code (exit 101). A ninth test directly isolates wrong-envelope
  acceptance on a valid ledger. Removing only the new shape precheck made
  that test fail with accepted=true; this extra experiment is a mutation
  check, not a claim that the integrated tree was the unchanged baseline.
- Locks: [`bundle_shape_tests.rs`](../crates/guard-verify/src/attenu/bundle_shape_tests.rs)
  covers both APIs, wrong shapes, per-member counts, early stop, null/absent
  positive controls, physical indices and ordinary JSON compatibility.

### Seccomp preparation and errors crossed the fork boundary unsafely

**Severity: Medium availability and error-classification defect; defense in
depth for the Linux execution boundary.** The original silent-skip behavior
in [#161](https://github.com/XuebinMa/agent-guard/issues/161) was already
replaced by required-name rejection in #163 / 0.2.6. The current baseline
still performed allocating libseccomp preparation inside `pre_exec`, which
can deadlock after a multithreaded fork. Rust's Unix spawn transport also
discarded custom setup-error text, turning it into generic errno 22 and
misclassifying it as `ExecutionFailed`. This review did not demonstrate a
current fail-open execution or a deterministic deadlock.

- Paths: [`linux.rs`](../crates/agent-guard-sandbox/src/linux.rs) and
  [`native_seccomp.rs`](../crates/agent-guard-sandbox/src/linux/native_seccomp.rs).
- Patch: resolve required names, construct all rules and export BPF in the
  parent. Decode bounded native-endian fields into aligned instructions;
  never cast an unaligned byte buffer into `sock_filter`.
- Child: use immutable preallocated instructions and raw `prctl` calls only.
  A private close-on-exec, nonblocking pipe transports a fixed-size stage and
  errno. Parent reconstruction preserves `FilterSetup`; ordinary chdir/exec
  errors remain `ExecutionFailed`. Invalid reports fail closed and clean up
  any successfully spawned owned process. FullAccess remains explicitly
  unfiltered; builds without the feature do not run a compatibility shell.
- Compatibility cost: the private export memfd requires Linux 3.17+ and a
  host policy permitting `memfd_create`. Missing support fails closed. This
  is not a claim that every kernel above that minimum was tested.
- Red: the six native failure/positive controls had 2 passes / 4 failures
  before the fix (exit 101). Required-name diagnostics became generic
  `ExecutionFailed`; missing-dir validation ran before the intended preflight.
- Green: required-name failure, real kernel invalid-BPF rejection, real
  `no_new_privs` rejection and no-command markers now pass. Additional tests
  cover BPF length/alignment, malformed report frames, open-writer handling,
  four threads x three executions under a shared bound, and same-file
  unsandboxed/read-only/workspace-write controls. No new security test is
  ignored or filtered out of the dedicated Linux CI job.

## Actual validation

macOS arm64 used Rust 1.94.1, Python 3.14.2 and Node 25.6.0:

- `./scripts/verify.sh full`: exit 0, including guard-verify 90/90,
  Python 108 passed / 1 optional-framework skip, Node binding suites and
  plugin 14/14. The first sandbox-restricted run could not bind a broker
  loopback port; the complete gate was rerun with the normal local network
  permission, not by skipping that test. Existing ignored Rust performance
  and subprocess-helper tests were not reclassified as passing tests.
- Strict workspace all-feature/all-target Clippy: exit 0.
- Freshly built Python and Node bindings: 70/70 Rust/Python/Node parity.
- Final documentation/format/whitespace checks: exit 0 (52 script tests;
  85 Markdown files inspected by the documentation gate).

Actual Linux validation ran in Docker Desktop's Linux VM, not a macOS cfg
stub: Linux 6.10.14-linuxkit aarch64, libseccomp-dev 2.5.4-1+deb12u1,
Rust/Cargo 1.99.0. The official Rust image was pinned at
`sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6`.
It had a read-only source mount, no privileged mode, extra capabilities,
Docker socket or credentials, and bounded CPU/memory/PIDs/test deadlines.

Final Linux commands (all with `--locked`, all exit 0):

```bash
cargo test -p agent-guard-sandbox --features seccomp --lib -- --nocapture
cargo test -p agent-guard-sandbox --features seccomp --test seccomp_integration -- --nocapture
cargo clippy -p agent-guard-sandbox --features seccomp --all-targets -- -D warnings
cargo test -p agent-guard-sandbox --lib
```

Results: 21 unit / 14 integration / 12 no-feature tests, zero failures and
zero ignored. Linux-only strict lint initially found three modern style
requirements; they were corrected without suppressions or raising the
declared MSRV. Dedicated Linux CI now runs the complete `linux::` unit
subset (including failure protocol and concurrency) plus integration tests,
with a ten-minute job limit. Hosted CI must still run on the final head.
The dedicated local container was removed after validation; source, image
digest and host-side logs were retained.

Local raw log SHA-256 fingerprints (temporary logs are not a permanent store):

| Log | SHA-256 |
| --- | --- |
| Native red, six tests | `266064708884667076282d7a01bb419fdbbee7e37a8c0a7f90224c5a37889b7c` |
| Final Linux unit | `56d2459efd9862f3f6425adc8249e7acab06f351137fffddba4a4b09f6bcc7b3` |
| Final Linux integration | `6947e4ebcce971e4d370db4d2025b8a041577d91e466b6dc3c4853c748d30f48` |
| Final Linux strict lint | `c80c4ba186ea79224875c8f7b5ea95a858ed7605ec8cdb23ddea7f2cf57343c8` |
| Final Linux no-feature | `075a07449095132643dd60beee83baa32a5f361cba1712e6a2a466b1ac52d0ae` |
| Full local gate | `bf5b5dec82c7433a1677ccdbca723e3a80e6a715c036c1733bbae19cdc4b195a` |
| Fresh binding parity | `48ccf19230aeed32b8e835f88e00dad541cc15cc87fc7dba98be297731521118` |

## Contract provenance and what remains open

The verifier was implemented against the public
[contract at b62b3fa](https://github.com/attenu-io/attenu-guard/blob/b62b3fa38feebc071ae384992e6c383c1e645ea7/tests/vectors/README.md)
and [upstream clarification](https://github.com/a2aproject/A2A/issues/1575#issuecomment-6131047511),
without reading, porting or running its reference verifier implementations.
The pinned local corpus remains v1.4, 20 cases, SHA-256
`58d3546d67b1bafd8c96e0a01ae80b4b722f46af3459f19ee2b0ef34893da00d`.
Those 20 passing cases do not independently validate the new schema rules;
the negative local regressions do. v1.5 is not yet available and has no score.
Fractional `ttl` interoperability was not resolved or silently changed.

This is actual seccomp syscall acceptance on one Linux VM configuration,
not native-host broker/container credential-isolation acceptance, universal
architecture coverage or a proof that all post-fork activity is safe. The
new installation callback was reviewed specifically for allocation/locking;
the bounded concurrency test is not proof of deadlock impossibility.
Old-kernel/memfd-denied error branches were not separately fault-injected.
Windows ambient handles and general shared-hard-link containment remain open.
No source-version or published-release marker was bumped, and no cancelled automation was
restarted. Future v1.5 validation and public delivery require their real gates.
