# README A/B Draft — 2026-05-09

> **Status: shipped.** Version B was adopted into the live `README.md`
> on 2026-05-21 (Phase 1, Sprint 5-1) per the decision criteria in
> §"Decision criteria" below. This file is retained as the design record
> showing why the framing changed; the live README is the source of truth.

## Goal

Decide whether to keep the existing "execution control layer for agent side
effects" framing, or shift to "outbound change control for AI coding agents
(action + content)". The strategic argument for the shift is in
`docs/strategy/competitive-snapshot-2026-05.md` and
`memory/project_strategic_direction_2026_05.md`. This document presents both
choices side-by-side so the community vote is on real text, not abstract pitches.

---

## Version A — current (no change)

This is the live `README.md` top section as of 2026-05-09 (lines 1-22 of
`README.md`):

```markdown
# agent-guard

> The execution control layer for agent side effects.
> When an agent is about to do something real, `agent-guard` decides whether to
> execute it, deny it, ask for approval, or hand it back to the host.

[![Version](https://img.shields.io/badge/Version-0.2.0--rc1-blue.svg)]()
[![Focus](https://img.shields.io/badge/Focus-Execution%20Control-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)]()
[![MSRV](https://img.shields.io/badge/MSRV-1.79-orange.svg)]()

`agent-guard` is for AI application and agent developers who need a real
execution boundary before tool calls turn into shell commands, file mutations,
or other side effects. It sits between agent intent and execution so risky
actions do not rely only on prompts, regexes, or ad hoc handler code.

Today, the clearest short-term wedge is side-effect execution control across a
very small set of high-risk actions:

- shell / terminal
- file write
- outbound mutation HTTP
- one runtime decision surface for `execute | deny | ask_for_approval | handoff`

That narrow wedge is the adoption point, not the final scope. The project can
grow into broader side-effect control over time, but the reason to use it now is
simple: it gives your agent a real execution decision point where side effects
become real.
```

### What Version A optimizes for

- Engineering precision (exact runtime semantics in tagline)
- "Layer" framing — accurate to architecture
- No commitment to a specific user persona

### What Version A misses

- No specific user moment ("when does this matter?")
- No "why now" — reads as a future-proof tool, not an urgent one
- Phrase "execution control layer for agent side effects" is hard to repeat
  back; not a buyer's mental model
- Doesn't differentiate from cloud sandbox runtimes (E2B, Modal, Daytona) or
  LLM I/O guardrails (NeMo, Lakera, Guardrails AI) — readers may assume overlap
- Does not name the buyer (AI app developer ≈ everyone working on AI)

---

## Version B — proposed (new framing)

```markdown
# agent-guard

> Outbound change control for AI coding agents — action and content.
> Your agent writes code and runs tests freely; the moment it tries to push,
> publish, deploy, or send a secret out, `agent-guard` is the gate.

[![Version](https://img.shields.io/badge/Version-0.2.0--rc1-blue.svg)]()
[![Focus](https://img.shields.io/badge/Focus-Outbound%20Control-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)]()
[![MSRV](https://img.shields.io/badge/MSRV-1.79-orange.svg)]()

`agent-guard` is for developers running AI coding agents — Claude Code, Cursor,
Codex CLI, Aider — who don't want the next `git push --force` to be the agent's
idea, and don't want a stray `.env` quietly making it into the model's context.

Two layers of outbound control, one decision surface:

- **Action layer** (today): gate `git push`, `npm publish`, `docker push`,
  `gh release create`, non-local HTTP mutations, `rm -rf` — before they become real
- **Content layer** (Sprint 6): detect credentials and PII in tool inputs and
  outputs before they reach the LLM provider or external API
- **Audit layer**: every decision signed with Ed25519 — tamper-evident receipts
  ready for EU AI Act articles 28-31 evidence

Best fit: solo and small-team devs running coding agents in real workflows.
**Local-first by design** — no cloud, no telemetry, no data leaves your machine.

Why now: EU AI Act enforcement begins 2026-08-02. Claude Code's PreToolUse hook
has known gaps with MCP tools (#33106). DNS-tunnel credential exfiltration
exploits (CVE-2025-55284) are already in the wild. The cost of "the agent did
something irreversible" is no longer hypothetical.
```

### What Version B optimizes for

- A specific user moment: "the agent wants to push / publish / deploy"
- Names the runtimes the buyer is actually using (Claude Code, Cursor, ...)
- "Why now" is a forcing function (regulation + named CVEs + named bug)
- Two-layer structure makes the content-layer roadmap explicit, not hidden
- "Local-first" + "no telemetry" — explicit anti-cloud positioning, the half
  of the moat big-cloud vendors structurally cannot serve

### What Version B costs

- Loses some generality — "AI coding agents" is narrower than "AI applications".
  We accept that: the wedge is exactly that narrow.
- Mentions Sprint 6 in README, which couples README to roadmap state. Mitigation:
  remove that hint after Sprint 6 ships.
- "Outbound" terminology is fresh; some readers will need 1 sentence to grok.
  Tagline does the work.

---

## What's identical between A and B

- Version badge, license, MSRV
- Best-fit posture (no false enterprise claims)
- Honest scope ("today" vs aspirational)

## Side-by-side feature comparison

| Aspect | Version A | Version B |
|---|---|---|
| Tagline | "Execution control layer for agent side effects" | "Outbound change control for AI coding agents — action and content" |
| Named user | "AI application and agent developers" | "Developers running Claude Code, Cursor, Codex CLI, Aider" |
| User moment | None explicit | "Next `git push --force`, stray `.env`" |
| Why-now | None | EU AI Act 2026-08-02, #33106, CVE-2025-55284 |
| Layer structure | Single-layer (side effects) | Two-layer (action + content) |
| Audit story | Implicit | Explicit — Ed25519, EU AI Act 28-31 |
| Privacy posture | Not stated | "Local-first, no cloud, no telemetry" |
| Calls out competition | No | Indirectly, by what it isn't (no cloud, no telemetry) |

## Discussion prompts for the GitHub poll

Suggested seed questions for the Discussion thread:

1. Which tagline is closer to how you'd describe `agent-guard` to a colleague?
2. Does the two-layer (action + content) framing in B clarify what the project
   does, or does it overload the README?
3. Is the explicit mention of Claude Code / Cursor / Codex CLI helpful, or does
   it feel exclusionary if you're using a different runtime?
4. Does the "why now" paragraph (EU AI Act, #33106, CVE) make the project feel
   timely, or alarmist?
5. If you're a current user: did you reach for `agent-guard` because of side-
   effect control in general, or because of a specific outbound moment (push,
   publish, deploy)? B is betting it's the latter.

## Decision criteria

Default to Version B unless community feedback surfaces a concrete reason A is
better understood. Ship via S5-1 once feedback is in (Phase 1, ~2026-05-15).

## Out of scope for this A/B

- Body of the README (best-fit, current-scope, fastest paths) — those are
  Sprint 5-3 / 5-4 / 5-5 work.
- Marketing copy outside README (X, HN, ECC marketplace) — those derive from
  whichever version wins.

Last updated: 2026-05-09. Working draft.
