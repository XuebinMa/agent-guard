# Broker Git deadlines and uncertain outcomes

Status: implementation in progress; not a released fix. Authorized by the
maintainer on 2026-10-22: start the bounded Broker timeout/recovery task.
Base: main `6751d9fb52c3eee14e939b1dc02376efd6fe571d`. Work stays in the
existing clean independent worktree; the original dirty checkout is untouched.
No version, release, advisory, CI-dependency upgrade or automation is authorized.

## Contract

1. Every production Broker Git call uses one bounded runner, including config
   reads and batch-check input. Preview and execution each get a fresh monotonic
   Git-operation budget, shared across their subprocesses; human confirmation
   does not consume execution's budget. Default 300 seconds; the trusted caller
   may choose a finite positive budget up to one hour.
2. No inherited stdin, shell interpolation, automatic push retry or grant replay.
   Output capture must not wait indefinitely for inherited pipe writers. Bound
   captured stdout/stderr and refuse excess rather than parse truncated data.
3. On timeout/error, terminate the managed process group/job and perform bounded
   leader reaping. Report cleanup failures. This is not containment of malicious
   trusted helpers which deliberately detach, nor a bound on uninterruptible
   kernel/filesystem/spawn calls or the snapshot's physical I/O.
4. Before the push command, refusal means this execution did not launch a push.
   After launch, timeout/transport/collection failure does not establish that the
   remote stayed unchanged. Record an indeterminate outcome, exact transaction
   and consumed grant. Only trusted Git porcelain identifying an exact rejected
   ref may retain a definite refusal; an acknowledged success remains pushed.
5. Print distinct CLI recovery instructions and a nonzero exit for uncertainty.
   Reconcile the exact URL/ref/OID independently before seeking a fresh preview;
   no automatic reconciliation write or second push. Preserve existing signed
   pushed/refused receipt bytes; document the additive outcome reader contract.

## Existing implementations checked before implementation

- [Rust Child](https://doc.rust-lang.org/std/process/struct.Child.html): dropping
  a child does not terminate or reap it. Waiting and pipe collection can block.
- [Python subprocess](https://docs.python.org/3/library/subprocess.html): timeout
  handling must terminate and finish cleanup; sequential pipe waiting can
  deadlock. This is a reference, not a Python dependency for production.
- [process-wrap 10.0.1](https://github.com/watchexec/process-wrap/tree/v10.0.1):
  maintained successor to deprecated command-group, Rust 1.87 minimum. Inspect
  its std ProcessGroup/JobObject implementation before reuse: Unix group
  signaling; Windows suspend/assign/resume avoids the child-assignment race.
  Pin the reviewed release and enable only required std/group/job features.
- [Windows jobs](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects):
  process-tree termination and membership are distinct from process permissions.
- [Git push porcelain](https://git-scm.com/docs/git-push#_output): machine-readable
  exact-ref status, rather than interpreting arbitrary stderr as a refusal.

No reference implementation of the Attenu verifier is read or changed here.
No claim about the existing Windows ambient-handle/shared-hard-link findings
changes because a subprocess runner uses a job object.

## Test-first sequence and acceptance

- [x] Safe finite Rust child fixtures first demonstrate the missing timeout,
  descendant cleanup, output cap and stdin/output positive controls.
- [x] Shared runner and deadline flow through all production Git entry points;
  no blocking `.output()`/`wait_with_output()` remains in that path.
- [x] Refusal vs uncertain push outcome, one-use grant, exact receipt and old
  signature/serialization regressions; no stderr-based success/refusal guesses.
- [x] Controlled authenticated loopback Git fixtures: stalled preview, stalled
  pre-push revalidation, and ref updated before delayed/lost response. Outer
  test deadlines and owned temporary resource cleanup are mandatory.
- [x] CLI budget validation, distinct uncertain-result output/exit, and truthful
  persistence/unsigned receipt behavior.
- [x] Broker/CLI targeted tests, full local verification, strict all-target lint
  and fresh binding parity. See the [checkpoint](../broker-git-deadline-progress.md)
  and [local evidence](../security-evidence/2026-10-22/broker-git-deadlines-local.json).
- [ ] Exact-head cross-platform CI before any merge.
  macOS local success is not Windows/Linux runtime acceptance.

Capture actual red/green and remaining limitations in a progress section below.
Do not turn a plan or successful synthetic fixture into a universal guarantee.
