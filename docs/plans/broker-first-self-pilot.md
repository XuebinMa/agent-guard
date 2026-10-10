# Broker-first: maintainer self-pilot

Status: **partial**. The user chose self-use first on 2026-10-06 (Pacific time)
and completed a human-operated macOS CLI-only rehearsal on 2026-10-09.
A useful development-task pilot, native Linux maintainer trial and representative
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
Production Git calls still do not promise finite deadlines. Windows inherited
handles and general shared hard links remain open.

P5 is complete only after actual task/feedback and representative operating
capacity are recorded with their limits. Choosing self-use, successful synthetic
CI or publishing a maintenance version alone does not complete it.
