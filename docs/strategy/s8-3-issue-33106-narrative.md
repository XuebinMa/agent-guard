# S8-3 — Issue #33106 Engagement Narrative (DRAFT — not posted)

| Field | Details |
| :--- | :--- |
| **Status** | 🟡 Draft for review — nothing posted |
| **Subject** | [anthropics/claude-code#33106](https://github.com/anthropics/claude-code/issues/33106) — *PreToolUse hook `permissionDecision: "deny"` not enforced for MCP server tool calls* |
| **Issue state** | CLOSED (unplanned) |
| **Author of this draft** | maintainer |
| **Last reviewed** | 2026-05-30 |

---

## Why this issue matters to agent-guard

agent-guard's Claude Code integration (`hooks/hooks.json` + `guard-hook`) is a
**PreToolUse hook that returns `permissionDecision: "deny"`**. #33106 reports
that this exact mechanism is **not enforced when the target tool is an MCP
server tool** — the hook fires, returns deny, and the MCP call proceeds anyway.

That is not a peripheral bug for us. It is the enforcement primitive our hook
distribution rests on. So the honest posture is: **say plainly where our hook
does and does not bite**, and show that the SDK path does not depend on the
hook's MCP behavior at all.

The trap to avoid: implying agent-guard "fixes" or "works around" #33106. It
does not. We scope around it.

## What is actually true (verify before claiming)

1. **Our hook matcher is `Bash|Write|Edit|WebFetch`** (`hooks/hooks.json`) —
   all *built-in* tools. The issue itself confirms built-in PreToolUse deny **is**
   enforced ("Built-in tool PreToolUse deny IS enforced (e.g., Bash hooks work)").
   So within its declared scope, our hook's deny is honored.
2. **We never claimed MCP coverage in the hook.** The Sprint 6 honesty note
   already records that the Claude Code hook is check-only and that content-layer
   enforcement lives in the SDK path. The plugin docs should state the MCP gap
   explicitly rather than letting a reader assume `mcp__*` calls are gated.
3. **The SDK path (`Guard::run`) does not go through the Claude Code hook.** A
   host that routes MCP tool intents through the Guard SDK enforces at the
   decision boundary regardless of #33106, because the deny is the SDK refusing
   to execute — not a hook signal the runtime may ignore.

If any of the above stops being true (e.g. the matcher changes, or the issue is
reopened/fixed), this narrative must be re-checked before use.

## The defensible message (one paragraph)

> agent-guard's Claude Code plugin gates the built-in tools where PreToolUse
> `deny` is actually enforced today — `Bash`, `Write`, `Edit`, `WebFetch`. It
> deliberately does **not** rely on hook-level denial for `mcp__*` tools,
> because that path is not currently enforced (anthropics/claude-code#33106).
> For agents that route MCP tool intents, enforcement belongs at the SDK
> decision boundary (`Guard::run`), where a deny means agent-guard refuses to
> execute rather than emitting a signal the runtime can drop.

## Where to say it (and where NOT to)

- **#33106 is CLOSED unplanned.** Do **not** post a "use our tool instead"
  comment on a closed Anthropic issue — it reads as hijacking and burns trust.
- The right home for this is **our own docs**, specifically the plugin guide's
  honest-scope section and the framework support matrix. Link *out* to #33106
  as the upstream reason; never imply endorsement or a fix.
- If (and only if) the issue is **reopened** or a maintainer asks "does any
  external tool handle this," a single factual comment is acceptable:

  > For built-in tools the PreToolUse deny path works as documented; we lean on
  > exactly that in agent-guard's plugin (matcher `Bash|Write|Edit|WebFetch`).
  > For MCP tools we don't depend on hook-level denial for the reason in this
  > issue — we enforce at the SDK boundary instead. Happy to share the hook
  > adapter if it's useful as a repro harness.

  No marketing, no links beyond the repo, no claim of having solved it.

## Doc change this narrative should drive (separate, reviewable edit)

Add a short "MCP tools are not gated by the hook" callout to
`docs/guides/operations/claude-code-plugin.md` and a row/footnote to
`docs/reference/framework-support-matrix.md`:

> **MCP tools (`mcp__*`): not gated by the plugin hook.** Claude Code does not
> currently enforce PreToolUse `deny` for MCP tool calls
> ([anthropics/claude-code#33106](https://github.com/anthropics/claude-code/issues/33106)).
> The agent-guard hook intentionally matches only built-in tools
> (`Bash`, `Write`, `Edit`, `WebFetch`). To gate MCP tool intents, route them
> through the Guard SDK (`Guard::run`), which enforces independently of hook
> behavior.

That doc edit is the real S8-3 deliverable. This file is the rationale + the
exact words to use *if* a conversation opens — it is not itself something to post.

## Checklist before this narrative is used anywhere

- [ ] `hooks/hooks.json` matcher is still `Bash|Write|Edit|WebFetch`
- [ ] #33106 state re-checked (still CLOSED / or reopened?)
- [ ] No claim that agent-guard "fixes" or "bypasses" the bug
- [ ] Outbound link points to the issue as *reason*, not as endorsement
- [ ] Plugin guide + support matrix carry the honest MCP-gap callout first
