# Broker-first operations and reproducible cost measurement

This guide covers the fixed Linux host-broker workflow and a separate synthetic
cost measurement. Follow the [deployment reference](../../../deploy/broker-first/README.md)
for protected installation, image review, permissions and the exact configuration;
this document does not create another deployment or authentication mechanism.

Configuration checks, host composition tests, native container acceptance, a
real user workflow, and publication are different milestones. Their actual
status belongs in the [implementation checkpoint](../../broker-first-progress.md).
Do not infer complete I1–I8 acceptance, user approval or a released fix from this
guide. The user chose self-use first and cancelled the old release; `v0.2.7`
remains immutable. Successor `0.2.8` preparation and real self-pilot completion
are separate; see the [delivery checkpoint](../../release-028-delivery.md).

## One complete workflow

1. Install reviewed host binaries/interpreter/launcher outside agent-writable
   state. Provision the private operator-owned control files and exact
   destination-scoped authentication as described in the reference. Review the
   pinned image: it contains the whole runtime, file tools, MCP and hooks, but
   no protected Git credentials or privileged host handler.
2. Initialize the **fresh** workspace once, then run `check`. A configuration
   pass is not isolation acceptance. Missing required native Docker, capabilities
   or protected paths is a refusal, not an advisory fallback with the same label.
3. Run `start`. The agent develops, tests and commits inside that environment.
   Do not import sensitive shared hard links, host HOME, authentication sockets,
   grants or container management authority into it.
4. Use a separate trusted host terminal—not a terminal that displayed raw agent
   logs—to run `push`. The launcher checks that terminal and stops the complete
   agent container before reading the repository. The human reads the exact
   URL/ref/old OID/new OID, policy and effect, then confirms or declines.
5. On confirmation, the broker consumes one authorization and revalidates the
   exact transaction, then pushes from its private temporary repository. The
   launcher leaves the agent container stopped on success, cancellation or
   failure. Restart development explicitly with `start` when appropriate.
6. Inspect the protected receipt directory and actual outcome. The CLI persists
   an **unsigned** `PushReceipt` only when execution reaches its receipt stage.
   Early refusal, preview failure or cancellation normally creates no such
   record. A write error or interrupted process is different: it can leave an
   unknown remote outcome, which must be checked before another attempt.

For an already provisioned installation, the fixed lifecycle is:

```bash
/usr/bin/python3 /opt/agent-guard/deploy/broker-first/launch.py check --config /srv/agent-guard-host/control/deployment.json
/usr/bin/python3 /opt/agent-guard/deploy/broker-first/launch.py start --config /srv/agent-guard-host/control/deployment.json
# Later, from a separate trusted host terminal:
/usr/bin/python3 /opt/agent-guard/deploy/broker-first/launch.py push --config /srv/agent-guard-host/control/deployment.json
```

Never expose this credential-bearing host path to the agent, MCP or a host tool
proxy. TTY checks do not authenticate a human against another process with the
same host permissions; account/process/terminal separation remains a prerequisite.
Do not add `--yes` or pipe an agent-supplied answer into the strict workflow.
Neither `doctor` nor a receipt proves that separation.

## Maintainer self-pilot

The first actual user is the maintainer. This is a valid pilot, not evidence
of demand from other users. Use the [self-pilot checklist and record](../../plans/broker-first-self-pilot.md)
to record one real development task, a declined preview, a separately approved
transaction and the observed approval/deployment cost. A CI PTY or benchmark
confirmation is not the maintainer's feedback.

The strict deployment requires a native Linux Docker host. A trial of the CLI
on macOS can evaluate preview wording and ordinary local workflow, but cannot
complete the Linux deployment or capacity acceptance. Do not install another
runtime, move a real repository or supply Git credentials merely to fill this
record without the operator choosing that setup.

## Failure and recovery guide

| Condition | What it establishes | Safe next step |
| --- | --- | --- |
| Human declines, or EOF before confirmation | No broker execution grant/push stage; preview may already have queried an authorized remote | Keep the agent stopped; review or restart development deliberately. Do not count absence of a receipt as a universal no-network result. |
| Transaction/policy changed after preview | The old approval no longer applies; an execution-stage refusal may already have consumed the grant | Resolve/review a fresh transaction. Never replay/edit a grant or weaken the lease. |
| Stale remote lease / rejected push | Git refused the attempted update; record the actual transaction and spent grant when a receipt is available | Establish current remote state through a trusted read-only operator path and review a new preview; do not force-push to make the test pass. |
| Destination outside configured authentication scope | The broker refuses before that destination's network query | Correct the intended exact repository alias or protected destination/config. Do not widen to an unscoped helper/header or follow arbitrary redirects. |
| Authentication or TLS certificate failure | The endpoint/credential/CA setup is unusable; this alone proves no isolation boundary | Validate the trusted scoped authentication/CA and a positive control. Do not disable certificate validation, forward agent credentials or use an anonymous destination as acceptance. |
| Unsupported repository layout | Linked worktree, partial clone, alternates, symlinks or multiple push URLs are outside the strict broker slice | Develop in a normal fresh checkout under the controlled runtime; do not run plain credential-bearing Git in the hostile checkout as a workaround. |
| Runtime/config/path/terminal prerequisite fails | The strict reference did not start that workflow | Repair protected setup using the reference. An explicitly labeled advisory installation is different, not a silent fallback or an isolation pass. |
| Disk/quota exhaustion or temporary-copy failure | Snapshot/record creation may fail; a free-space observation is not a reservation | Provide a dedicated quota-aware scratch/record filesystem. Inspect owned temporary state and remote outcome before retrying. Never recursively clean a workspace/home to make room. |
| Receipt persistence fails after execution | The remote may already have accepted the push even when no receipt file exists | Preserve stderr and establish actual remote state before another approval. Report missing local evidence; do not label the attempt unsuccessful merely because recording failed. |
| Process interrupted or remote query stalls | The terminal state may be unknown; absence of a receipt is not proof of no mutation | Keep the agent stopped, preserve diagnostics, check the exact remote ref through trusted operator tooling, and authorize a fresh attempt only after reconciliation. |

The current broker Git path does not itself promise a finite network/process
deadline; the deployment reference lists bounded broker/network execution as
separate work. The synthetic benchmark below adds an **external test-process**
deadline. That is not a production timeout fix. Killing a process is not a
transaction rollback or a guarantee that remote state is unchanged.

Partial workspace initialization remains visible. Inspect only known
operator-owned generated paths before recovery; do not reuse a replaced volume
or bulk-delete user data. Shared-hard-link and Windows inherited-handle findings
remain open; this Linux workflow does not repair them.

## Reproducible synthetic measurement

No prior reusable broker snapshot benchmark exists in this checkout; the
Criterion benches cover policy/runtime/audit, not isolated repository cost.
The new [benchmark driver](../../../scripts/benchmark-broker-first.py) reuses
the existing CLI and its real broker snapshot path. It does not instrument or
replace production code, invoke Cargo, contact a network service, or read a user
credential store. The workload is entirely synthetic; source-checkout metadata
and the tracked diff are read only to report revision/state and a diff hash.

Use a freshly built, reviewed CLI from the exact source tree being measured.
The following operation creates and removes only owned temporary synthetic
repositories and local bare remotes:

```bash
python3 scripts/benchmark-broker-first.py --cli /absolute/path/to/agent-guard --sizes-mib 1,8,32 --iterations 2 --filesystem 'operator-verified filesystem type' --hardware 'operator-verified model and RAM'
```

Stdout is the JSON report; progress/errors go to stderr. Save that report using
the normal artifact workflow along with the exact source revision/diff. No
credentials belong in the `--filesystem` or `--hardware` descriptions. Optional
`--temp-parent` selects an existing local scratch filesystem; the driver always
creates its own private temporary child, not a cleanup target supplied by the
operator.

Method and limits:

- Exactly three distinct increasing payload sizes, default **1/8/32 MiB**;
  each is capped at **128 MiB**, with at most three iterations per size.
- Fixed public pseudo-random seed, synthetic identity/date, one file, one tree
  and one commit; objects are repacked. The payload hash and actual primary
  object bytes are recorded. These are size-stratified examples, not a
  representative history/file-count/compression model for production.
- Every subprocess has a configurable 5–120 second deadline (60 default), with
  a ten-minute overall driver deadline checked between operations. On a child
  timeout the driver terminates only its owned process group. Ordinary Python
  file I/O/temporary cleanup still relies on a responsive local filesystem;
  these limits do not make a hung kernel/storage device bounded.
- A conservative free-space precheck is a point-in-time budget, not reserved
  space or a quota. The benchmark can still fail if another process fills it.
- Each iteration first measures a declined preview, then an approved creation
  push to a fresh local bare remote. The latter includes a second preview plus
  execution re-snapshot, validation/fsck and local transport. Both values are
  **whole CLI wall time, not pure copying time**; subtracting them does not
  isolate copy cost.
- The driver enables `--allow-local-file-remote` only for these synthetic
  fixtures with an explicit empty private Git config. It supplies its own
  public test confirmation input, not human-authentication evidence. The
  protected production launcher does not offer this transport/approval bypass.
- A 10 ms sampler observes only the broker's per-trial private `TMPDIR`.
  `sampled_maximum` is the largest observed regular-file count, **not a true
  peak**; short-lived files can be missed. Directory metadata, repository,
  remote, working payload, RSS and whole-host usage are excluded. Summed
  `st_blocks` is an allocation estimate, not unique physical disk usage on
  sparse/reflink/compressed/shared-extent filesystems.
- There is no page-cache flush. Data was generated/repacked recently, so neither
  the first trial nor later trials is called a cold-cache measurement. Sampling
  itself adds I/O. Record concurrent workload rather than treating these times
  as an isolated-machine performance guarantee.
- Before timing each trial, `git --version` establishes the operating-system
  toolchain cache baseline in that same scratch directory. For example, Apple's
  Git shim can retain `xcrun_db`; the report records baseline/after file names and
  bytes, includes those files in sampled maxima, and refuses a changed remaining
  file set. A toolchain cache file is not evidence of an unremoved broker snapshot.
- Each successful result independently verifies the bare remote's exact ref
  against the transaction/unsigned receipt, including `pushed` and a grant ID.
  Declined preview must leave no ref or execution receipt. Failures exit nonzero;
  do not present partial/missing observations as completed measurements.
- The report records source SHA, before/after dirty state and tracked diff hash,
  benchmark-script/binary hashes and versions, OS/CPU/statvfs information and
  operator-supplied filesystem/hardware description. Untracked contents are
  **not** covered by the tracked diff hash; save those source files separately.
  A dirty source report plus a binary hash is not proof that the binary was
  built from every uncommitted file.

Benchmark-method unit tests are independent of the security acceptance suites:

```bash
python3 -m unittest discover -s scripts/tests -p test_benchmark_broker_first.py -v
```

### Recorded run

One completed run started at **2026-10-06T20:05:50Z**, with the defaults above:
two iterations of each size, 10 ms sampling and 60 s subprocess deadlines.
Host: Mac15,6 / Apple M3 Pro / 18 GiB RAM / 12 logical CPUs, macOS 26.6.2 arm64,
Python 3.14.2 and Apple Git 2.50.1. Scratch was on the APFS Data volume under
`/private/tmp` (4,096-byte filesystem blocks). Cache was not flushed; other
verification/CI preparation could run concurrently. No isolated-machine or
cold-cache result is claimed.

| Synthetic payload | Primary object bytes (logical) | Declined preview, trials 1 / 2 (s) | Approved CLI including preview and push, trials 1 / 2 (s) | Sampled TMPDIR maximum, logical / allocated estimate (bytes) |
| --- | ---: | ---: | ---: | ---: |
| 1 MiB | 1,050,400 | 0.129 / 0.123 | 0.319 / 0.309 | 1,051,883 / 1,077,248 |
| 8 MiB | 8,392,672 | 0.132 / 0.133 | 0.473 / 0.467 | 8,394,155 / 8,417,280 |
| 32 MiB | 33,566,177 | 0.173 / 0.150 | 0.993 / 0.993 | 33,567,661 / 33,591,296 |

The sampled maximum was identical across both preview/push trials for each
size. All six approved pushes had matching independent remote refs, `pushed`
unsigned receipts and consumed grant IDs; all six declined previews left no ref
or execution receipt. There were no sampler errors. In every trial the only
remaining scratch file was the prewarmed `xcrun_db` baseline: 1,127 logical
bytes / 4,096 allocated estimate before and after. It is included in the table.
An initial attempt exited nonzero because it mistook that Git-shim cache for a
snapshot leak; no timings from that failed attempt are reported.

Reproducibility bindings from the successful JSON report:

- Source HEAD before/after:
  `c1f9ee1a4ac516b8afc05c4228c913ca44b1bc3a`.
- Source was dirty with these new P5 files and native acceptance files untracked.
  A new untracked `authorization_boundary.rs` test appeared during the run, so
  `source_changed_during_run` is **true**. The tracked diff was empty before and
  after (SHA-256
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
  This is not a claim that the whole checkout was frozen or all untracked source
  was included in the binary.
- CLI SHA-256, checked unchanged after the run:
  `9492e711f315955a9283f5897f9826628fe0944e0e093b819c23d05acfd31059`.
  Its `agent-guard 0.2.7` version string is not proof of publication.
- Benchmark driver SHA-256:
  `278dbef5974096ce0805390a772fea8cdcb51ed3ac8040126410adcae580ef9f`.
- Payload SHA-256 values, respectively:
  `35c8ce2a8daa4fe30c4e7b7e58ef48e91f0ecd109a2b8968f51eca6b954e6e08`,
  `0c6c0d8f399df5fb21c5c05c1b0305a29e6d8af814c492567056af454d8c6428`,
  `fe977ffdf0dd243b9e481f4a0680346ed1884c60fb5d64504883c70130dcd767`.

This is a completed **synthetic size-stratified observation**, not pure copy
time, a true temporary disk peak, an authentication/container test or acceptance
of real large-repository operating cost. Robust physical peak accounting and
representative user/repository evidence remain separate
work. Do not extrapolate from these three one-blob fixtures.

### Direct copy-phase measurement (test-only)

An optional [Rust test probe](../../../crates/agent-guard-broker/src/git/snapshot_cost.rs)
now times the four existing copy functions directly, separately from complete
`GitSnapshot::capture`. It is compiled only for Unix crate tests and has **no
production instrumentation, networking or public API**. The opt-in performance
test is ignored in the ordinary test suite because it needs the driver's owned
fixture; this is not a skipped security acceptance test. The benchmark below
explicitly invoked it six times successfully.

Build both artifacts from the reviewed source tree:

```bash
cargo build -p agent-guard-cli --locked
cargo test -p agent-guard-broker --lib --locked --no-run
```

Cargo prints the unit-test executable path, including its current hash. Supply
that exact executable as `--copy-probe` to the benchmark command above; do not
select an old test binary by a wildcard. The driver supplies only its temporary
repository/empty private config, preserves its cleared environment and bounds
the process using the same watchdog. Reports require one JSON marker, matching
candidate OID, finite nonnegative timings and valid byte counts; a success
banner or malformed report is not accepted. Both binaries are hashed before
and after measurement.

The timer includes object/ref filtering, metadata/race checks and copying; it
excludes setup, config parsing, Git/fsck and network. For the immutable fixture,
the copy functions create each selected file once and retain it, so the final
**logical copy-data high-water** is exact for this phase. `st_blocks` is still
only an allocation estimate; directory metadata, delayed/shared/compressed
physical allocation and other processes are not measured. The full capture's
held file count is a separate point-in-time count, not the whole CLI peak.
The validated capture is dropped before the timed independent copy, avoiding
two simultaneously retained snapshots in the probe. Capture runs before copy,
and the probe runs before CLI timing, so caches are warm: do not compare these
CLI times with the earlier no-probe run as an optimization result.

The [raw copy report](../../security-evidence/2026-10-06/native-linux/copy-cost.json)
started at **2026-10-06T22:23:48.987950Z** on the same Mac/APFS host. Source HEAD
was `5f8e714` with these uncommitted additions; before/after state was identical
(`source_changed_during_run: false`). The diff hash does not cover untracked
contents. CLI SHA-256 was
`f97a47cbd1a15fdb8788165536679afcc62881d6165bc4e44d2ee0e233786707`;
test probe SHA-256 was
`0112a03cd7cbb9139f61ea42be9b96deff2fa322b496058139780c81e50a8a9f`.
The report retains its actual driver hash; later explanatory metadata/docs
edits are not retroactively included in that run.

| Synthetic payload | Copy phase, trials 1 / 2 (s) | Complete capture, trials 1 / 2 (s) | Retained copy data, logical / allocated estimate (bytes) | Complete held snapshot, logical (bytes) |
| --- | ---: | ---: | ---: | ---: |
| 1 MiB | 0.00114 / 0.00146 | 0.08255 / 0.07944 | 1,050,323 / 1,060,864 | 1,050,800 |
| 8 MiB | 0.00499 / 0.00501 | 0.08456 / 0.08380 | 8,392,595 / 8,400,896 | 8,393,072 |
| 32 MiB | 0.02462 / 0.02693 | 0.10640 / 0.10652 | 33,566,100 / 33,574,912 | 33,566,578 |

All six reports matched the actual candidate. All six approved local pushes
still independently matched refs/unsigned receipts and an actual spent-grant
file; declined previews left no ref/receipt. An initial attempt failed because
libtest prefixed the output marker: the emitter was corrected to use a separate
line, without weakening the report parser. No timings from that failed attempt
are adopted. These small warm one-blob cases are not production capacity or a
true physical peak; representative workload/host and real-user pilot are pending.

## Remaining acceptance

The [plan](../../plans/broker-first-development-plan.md) requires native
container I1–I8 evidence and an actual user task. The fixed synthetic native
profile now has [actual evidence](../../security-evidence/2026-10-06/native-linux/README.md);
real user acceptance remains outstanding. Those are separate from this
benchmark and guide. Representative operational capacity, deployment viability
and genuine user feedback remain pending until measured/observed; do not invent
positive feedback or mark P5/the entire plan complete from synthetic numbers.
No new release, tag movement, registry upload or advisory change is authorized
by a benchmark result.
