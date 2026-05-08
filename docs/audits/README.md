# `docs/audits/` — Layer 3 weekly deep-audit reports

This directory holds the auto-generated **weekly deep-audit** reports for
agent-guard. Each report is the combined output of three reviewer agents
run in parallel against the security-critical surface.

| filename                         | source                                          |
| -------------------------------- | ----------------------------------------------- |
| `YYYY-MM-DD.md`                  | one weekly run, agents aggregated into one file |
| `YYYY-MM-DD-2.md`, `-3.md`, …    | same-day re-runs (manual or retry)              |

The driver lives at [`.claude/workflows/weekly-deep-audit.sh`](../../.claude/workflows/weekly-deep-audit.sh).

## What runs each week

The script invokes three `claude -p` subprocesses **in parallel**:

| agent                    | scope                                                  | failure mode |
| ------------------------ | ------------------------------------------------------ | ------------ |
| `silent-failure-hunter`  | SDK + validators + sandbox                             | swallowed errors, bad fallbacks, missing error propagation |
| `security-bounty-hunter` | validators + sandbox + policy + signing + executors    | validator bypass, sandbox escape, signature forge, executor injection |
| `type-design-analyzer`   | `GuardDecision` / `DecisionCode` / `TrustLevel` / `PolicyMode` | invariants not expressed in the type, illegal-state representability |

Each agent's prompt is hard-coded in the script; see the `PROMPT_*` heredocs
near the top for the exact briefs and the "out of scope" carve-outs.

## Schedule registration (per-machine, one-time)

The cron itself is **not committed** because schedule entries are
per-user state. Set it up once on whichever machine should run the audit:

```text
# In a Claude Code session
/schedule
```

When prompted, register a routine with these settings:

- **Cron**: `0 9 * * 1` (Monday 09:00 local)
- **Prompt**: `bash .claude/workflows/weekly-deep-audit.sh`
- **Working directory**: the agent-guard repo root

Verify the registration with `/schedule list`. The next firing should
show as the upcoming Monday 09:00 in your local timezone.

If you prefer system cron over the Claude routine system, the equivalent
crontab line is:

```cron
0 9 * * 1   cd /path/to/agent-guard && bash .claude/workflows/weekly-deep-audit.sh
```

## Manual runs

You can trigger the audit any time:

```bash
# All three agents (real LLM dispatch — minutes, not seconds)
bash .claude/workflows/weekly-deep-audit.sh

# Just one agent
bash .claude/workflows/weekly-deep-audit.sh --agent security-bounty

# Print the prompts without invoking claude -p (cheap; for verifying scaffolding)
bash .claude/workflows/weekly-deep-audit.sh --dry-run
```

The script writes to `docs/audits/YYYY-MM-DD.md`; if today's file already
exists it appends a `-2`, `-3`, … suffix so you never clobber an earlier
run.

## How to triage a report

1. Open the most recent `YYYY-MM-DD.md`.
2. The report opens with a status table — confirm all three agents ran
   `ok`. If any are `fail`, re-run that agent manually with `--agent`.
3. Read each `### Findings` section. Convert anything **CRITICAL** into a
   GitHub issue or fix PR before the next Monday firing.
4. **HIGH** findings should at minimum get an issue; **MEDIUM** / **LOW**
   are informational unless a pattern repeats across multiple weekly runs.
5. If a finding is a known false positive, narrow the agent's prompt in
   `weekly-deep-audit.sh` to reduce noise on the next run.

## Layer 1 — real-time edit-time review

The Layer-1 hook lives at [`.claude/workflows/post-edit-review.sh`](../../.claude/workflows/post-edit-review.sh)
and is wired into `.claude/settings.json` as a `PostToolUse` hook on
`Edit|Write`. It fires after every successful Edit/Write on a `.rs`
file and runs the **same deterministic CRITICAL-pattern scan** Layer 2
applies at commit time, but on the just-written region only and
scoped to files whose `audit-rules.yaml` rule has
`severity_block: CRITICAL`.

| where                                       | what it stores                                 |
| ------------------------------------------- | ---------------------------------------------- |
| `.claude/.audit-state/findings.log`         | append-only timestamped findings; tail this    |
| `.claude/.audit-state/stamps/<sha256>.stamp` | per-path debounce stamp (mtime is the timestamp) |

`.claude/.audit-state/` is gitignored; nothing here ever gets committed.

**Debounce.** Layer 1 enforces a 5-second per-path debounce: bursting
ten edits to the same file in a second produces at most one log entry
and one stderr summary. Editing ten *different* files in a burst still
produces ten reports — each path has its own stamp.

**Tailing findings live (in another terminal):**

```bash
tail -F .claude/.audit-state/findings.log
```

Each line is:

```
<YYYY-MM-DDTHH:MM:SS>  <rel_path>:<line>  CRITICAL  rule=<rule_id>  reviewers=<csv>  <msg> :: <snippet>
```

The `reviewers=` field is sourced from the matched rule's `reviewers:`
list and records which LLM agents *would* be dispatched if real LLM
review were enabled. Today Layer 1 ships **deterministic-only** —
spawning real reviewer agents on every Edit (typical session: dozens
of edits) would burn tens of dollars per active developer per day.
The `reviewers=` provenance keeps the routing decision settled so a
later opt-in PR can flip the dispatch on without re-routing.

**Skipping the hook:**

| how                                  | when                                        |
| ------------------------------------ | ------------------------------------------- |
| `AGENT_GUARD_SKIP_POSTEDIT=1`        | global override (emergency / quiet sessions) |
| Edits to files under `.claude/`      | always skipped (defensive — prevents recursion if a future agent writes config there) |

Layer 1 is **warn-only** — the hook always exits 0. The only
observable effects are the appended log line and the one-line stderr
summary surfaced back to the agent.

## Why this exists

This is the third layer of the three-layer audit workflow:

| layer | trigger                       | gate? | landing PR |
| ----- | ----------------------------- | ----- | ---------- |
| 1     | PostToolUse on `.rs` edit     | warn  | (this PR)  |
| 2     | PreCommit on `git commit ...` | block | [#33](https://github.com/XuebinMa/agent-guard/pull/33) |
| 3     | Weekly cron                   | none  | [#34](https://github.com/XuebinMa/agent-guard/pull/34) |

Layer 2 catches most regressions at the commit boundary using
deterministic patterns. Layer 3 fills the gaps with LLM-based reasoning
that's too expensive to run synchronously: invariant analysis, attack-
surface review, silent-failure hunting. Running it weekly trades
latency for depth — you don't get instant feedback, but you do get a
fresh attacker-eye review every week without anyone manually
remembering to ask for one.
