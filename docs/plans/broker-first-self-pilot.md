# Broker-first: maintainer self-pilot

Status: **partial**. The user chose self-use first on 2026-10-06 (Pacific time)
and completed a human-operated macOS CLI-only synthetic rehearsal and an actual
project documentation-task exercise on 2026-10-09, followed by a human-operated
0.2.10 macOS CLI upgrade rehearsal on 2026-10-24. Task usefulness has not been
separately confirmed; the native Linux maintainer trial and representative
operating-capacity measurements remain pending. This record is not CI acceptance,
external customer evidence or publication authorization beyond the separate
[successor decision](../release-028-delivery.md).

## Completed macOS CLI-only rehearsal — 2026-10-09

The maintainer used a real Mac terminal to inspect a fresh preview, personally
decline with `n`, then inspect the same intended effect again and approve with
`y`. This was a harmless synthetic commit, not a useful project-development task.
The owned authenticated HTTPS fixture listened only on loopback; no real
credentials or external remote were used. The local helper reused the
[existing authenticated Git fixture](../../tests/broker-first/local_git_service.py),
not a new deployment backend.

| Observation | Maintainer result |
| --- | --- |
| CLI | `agent-guard 0.2.8`; source checkout `ca1a92baa1699a07d9c02074b5c7255f469d10ed` |
| Binary SHA-256 | `14d54d3d9572d5f0d773fede42da27c80a0c980c78c2dc6d96106bbc64bc34a9` |
| Intended destination | `https://127.0.0.1:55856/repo.git`, branch `main` |
| Candidate OID | `86dbad15e65f792778d160c325b6e2e9fadc0272` |
| Declined preview | Independent remote refs unchanged; no execution receipt, grant record or receive-pack request |
| Approved preview | Exact remote refs, unsigned receipt and consumed grant agreed |
| Cleanup | Helper reported cleanup complete; subsequent filesystem check confirmed the temporary run directory was absent |
| Preview clarity and approval burden | Maintainer feedback: “清楚知道，没觉得繁琐” |

The [sanitized summary](../security-evidence/2026-10-09/mac-cli-summary.json)
is preserved verbatim from the local run, not a signed proof. Its SHA-256 is
`6a60532f8eca380d7fc80725fa5007a6d0d28f1c86276ace75b4a19c43666bcd`.
The synthetic repositories/config/keys were removed after the run. This is
positive feedback for this particular preview and confirmation flow, not proof
of recurring task usefulness, Linux credential isolation or representative
capacity. P5 is not complete; the remaining trial and capacity criteria below
still apply.

## Completed project documentation-task exercise — 2026-10-09

The maintainer requested a small change in this project: preserve the first
trial's summary and record its human feedback in this checklist. The two-file
documentation change passed `./scripts/verify.sh docs` and `git diff --check`
before the local commit. The maintainer then personally cancelled one preview
and approved a fresh preview of that actual commit using the same CLI binary
and existing local authenticated fixture. No automation supplied either answer.

| Observation | Maintainer result |
| --- | --- |
| Intended destination | `https://127.0.0.1:57277/repo.git`, branch `codex/self-pilot-docs` |
| Previous OID | `ca1a92baa1699a07d9c02074b5c7255f469d10ed` |
| Approved candidate OID | `1dabbc607549a932c019aa28e1a96711644c6d1b` |
| Effect | Normal fast-forward adding one documentation commit |
| Declined preview | Remote remained at previous OID; no execution receipt or grant record |
| Approved preview | Only the intended branch advanced; unsigned receipt and consumed grant matched both OIDs |
| Cleanup and retention | Temporary run removed; standalone project commit retained and checkout clean |
| Preview clarity and approval burden | Maintainer feedback: “仍然清楚、不繁琐” |

The [verbatim sanitized summary](../security-evidence/2026-10-09/mac-project-summary.json)
has SHA-256 `def2f0e9145dc65fdbf85a0ba174804c790bfc06f6040e93df4cf8d3362a9544`;
the [separate feedback record](../security-evidence/2026-10-09/mac-project-feedback.md)
distinguishes reported remote checks during the run from subsequent filesystem
checks. No real credentials or GitHub push were involved. The OIDs above name
the original trial, not the integrated documentation-record branch; preserving
the evidence does not repeat that push. This demonstrates a bounded macOS CLI workflow,
not native Linux isolation, task usefulness, recurring usability or capacity.
P5 therefore remains partial.

## Completed 0.2.10 human CLI upgrade rehearsal — 2026-10-24

The maintainer personally ran the reviewed helper in a Mac terminal, declined
the first preview with `n`, then approved a separately displayed preview with
`y`. The CLI inherited that terminal directly; no automation supplied either
answer. The temporary helper provided Chinese guidance around the CLI's fixed
English built-in preview, confirmation and result text. This is not an English
user study or automatic locale switching.

The trial used the actual registry-installed 0.2.10 binary and a normal local
copy of the real [#184 documentation commit](https://github.com/XuebinMa/agent-guard/pull/184).
An offline fixture using exact registry Broker 0.2.9 created one synthetic
legacy spent archive, then exited before the 0.2.10 consumer ran. This tests
retaining that historical entry during a new CLI workflow, not migrating a
real credential store or installing over the maintainer's global binaries.

| Observation | Maintainer result |
| --- | --- |
| Trial time | 2026-10-24, 12:12–12:13 PDT (`America/Los_Angeles`); original UTC timestamps retained in the summary |
| CLI | Published `agent-guard 0.2.10`, from the independently verified exact crates.io `--locked` installation |
| Binary SHA-256 | `cb6b289528d081605fa0787166854aa58c2e75835a67f606dff92dcd3d1e5e65` |
| Intended destination | `https://127.0.0.1:59991/repo.git`, temporary branch `main`, not GitHub |
| Previous OID | `2da78b1d0b4ad3e62ebc02c09a6d0dd27f836181` |
| Approved candidate OID | `226b6535715626e0bb480abd9f611533c239e327` |
| Effect | Ordinary fast-forward adding one actual project documentation commit |
| Declined preview | Independent remote ref unchanged; no new grant, execution receipt or receive-pack POST; historical bytes unchanged |
| Approved preview | Exactly one receive-pack POST; independent ref, exact URL/ref/old-new OIDs, unsigned receipt, fresh grant archive and permanent consumption marker agreed |
| Historical state | The synthetic 0.2.9 spent archive was not overwritten; new approval used a different ID |
| Cleanup | Helper reported owned runtime files and listening service cleaned; subsequent filesystem inspection confirmed the trial directory absent |
| Preview clarity and approval burden | Maintainer feedback: “清楚，但是如果是英文用户，是否是英文显示？操作不繁琐。” |

The [verbatim run summary](../security-evidence/2026-10-24/mac-cli-0210-summary.json)
has SHA-256 `26f60960d32780cbc640564bc975cc2a4731d1d9fe2e5aaf386802359063f221`.
It retains `human_feedback: not collected` as its run-time snapshot; the
[separate subsequent feedback](../security-evidence/2026-10-24/mac-cli-0210-feedback.md)
records the actual later user response instead of rewriting that evidence.
The summary also binds the helper, project bundle and fixture hashes. The
temporary helper is not a new product entry point or CI gate.

Cleanup here means removal of owned fixture files and closure of its listener,
not a general proof that arbitrary descendants can be stopped after external
interruption. Both observed CLI calls returned normally; the fixture recorded
no forced-stop cleanup uncertainty. No real credentials, global installation,
real grant store or GitHub destination was changed. The unsigned receipt is
not third-party cryptographic proof.

This is positive feedback for this one maintainer's macOS CLI experience with
Chinese demonstration guidance. Recurring task usefulness, other users'
experience, native Linux maintainer use and representative operating capacity
remain unverified. P5 remains partial.

## Keep the first trial small

Use one useful development task that the maintainer actually wants completed:
one harmless code or documentation change, its ordinary tests, one commit,
and one ordinary non-force branch push. The maintainer supplies the task,
reviewed runtime image, existing native Linux Docker host and intended branch.
Do not import an existing repository into the strict launcher's fresh workspace
or add a host handler, interactive attachment or another backend to make the
trial fit. The complete agent runtime/tools must remain inside its reviewed image.

Begin with the owned local authenticated fixture or an operator-selected test
destination. A real remote write requires the maintainer's explicit repository/
branch authorization. This document does not permit third-party writes, use real
tokens in a synthetic fixture, or add credentials to the agent image/workspace.

The current development Mac is not a native Linux deployment. A separate macOS
CLI wording/usability trial is useful, but must be recorded as such; it cannot
complete the strict Linux or representative-capacity acceptance. Docker Desktop
does not satisfy this first profile. Do not install a new host/runtime silently.

## Readiness and trial

1. Follow [protected setup](../../deploy/broker-first/README.md). Record exact
   source/binary/image/config identifiers (never config contents, credentials
   or raw terminal transcripts), host/OS/Docker and workspace ownership.
2. From the protected host installation, run the existing `check` then `start`
   commands in [the operations guide](../guides/operations/broker-first-operations.md).
   Missing prerequisites are a refusal, not a fallback counted as isolation.
3. Let the in-container runtime perform the chosen task and normal tests and
   create its commit. The maintainer judges task usefulness; no automated
   confirmation or CI synthetic agent substitutes for that judgment.
4. From a separate trusted host terminal, run the existing `push` lifecycle
   command. Read the URL, branch, old/new OID and effect; **decline** first.
   Confirm the container remains stopped, no execution receipt exists, and a
   trusted read-only remote check shows no ref change. Preview network activity
   is expected; no receipt alone is not proof of no network contact.
5. Deliberately restart/review the unchanged task if needed. Run a fresh host
   `push`, inspect its new preview, and approve only the intended transaction.
   Do not pipe an answer, use `--yes`, edit grants or weaken the lease.
6. Independently compare the remote ref with approved candidate OID and protected
   unsigned receipt. Confirm its grant is consumed. Do not call the record a
   signed proof or a credential-isolation certificate. If recording fails or
   the process stalls, reconcile the real ref before retrying.
7. Record setup, task, cancellation and approval effort. Give an honest verdict:
   useful enough to retain, needs one scoped usability fix, or not worthwhile.
   Do not expand the platform/tool scope in response to missing prerequisites.

Use the [fault guide](../guides/operations/broker-first-operations.md#failure-and-recovery-guide)
for failures; keep only owned trial state, reconcile outcomes and never bulk
delete a home/workspace or force-push to make a trial pass.

## Fill after the native Linux real-task trial

| Observation | Maintainer result |
| --- | --- |
| Trial date, operator and real task | Pending |
| Native Linux strict deployment or macOS CLI-only trial | Pending |
| Source SHA, binary hash/version, reviewed image ID | Pending |
| Host OS/kernel, Docker version, CPU/RAM/filesystem | Pending |
| Approved repository/branch (no credentials) | Pending |
| Normal build/tests and actual task usefulness | Pending |
| Setup/development effort and problems | Pending |
| Declined preview: remote unchanged, no execution receipt | Pending |
| Approved preview: exact URL/ref/old/new OID understood | Pending |
| Independent remote/unsigned record/spent grant agreement | Pending |
| Approval/recovery effort and usability verdict | Pending |

## Capacity remains a separate measurement

Record the intended primary object size and history/file-count/compression shape,
host scratch/quota budget, copy time and full workflow timing. Existing bounded
synthetic 1/8/32 MiB results do not represent a real workload; do not silently
raise the driver's 128 MiB cap or change its method to fit one.

Record how disk usage is measured, what is included and the cache/concurrency
conditions. Logical retained bytes and `st_blocks` sampling are not full unique
physical peaks, especially on shared-extent filesystems. If a trustworthy full
peak or cold-cache observation is unavailable, record **unmeasured**, not zero
or passed. Do not flush a live host's caches or impose a disk-exhaustion trial.
Published 0.2.9 Git calls do not promise finite deadlines; 0.2.10 delivers the
[bounded path and recovery contract](../guides/operations/broker-first-operations.md#bounded-git-operations--0210-and-later).
See the [verified delivery record](../release-0210-delivery.md). Windows inherited
handles and general shared hard links remain open.

P5 is complete only after actual task/feedback and representative operating
capacity are recorded with their limits. Choosing self-use, successful synthetic
CI or publishing a maintenance version alone does not complete it.
