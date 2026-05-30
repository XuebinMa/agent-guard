# S8-4 — Plugin Launch Outreach (DRAFT — nothing posted)

| Field | Details |
| :--- | :--- |
| **Status** | 🟡 Draft for review — do NOT post until the gating checklist below passes |
| **Occasion** | Sprint 8 ships Claude Code plugin distribution (one-command install) |
| **Channels** | X, Hacker News, Reddit |
| **Last reviewed** | 2026-05-30 |
| **Related** | [Launch Kit](../guides/adoption/launch-kit.md), [Social Post Templates](../guides/adoption/social-posts.md), [#33106 narrative](s8-3-issue-33106-narrative.md) |

---

## ⚠️ Gating checklist — must all be true before posting any of this

The copy below references commands a stranger will run. If a command does not
yet work for a fresh user, the post is dishonest. Verify:

- [x] **`npx agent-guard-plugin init` works for a non-checkout user** — the
      `agent-guard-plugin` package is **published to npm**. Published 2026-05-30 as
      `agent-guard-plugin@0.2.0-rc1` on the `latest` tag; `npx agent-guard-plugin@latest
      --help` verified to fetch and run from a clean cache. The `npx` variants below
      are now safe to post.
- [x] **`/plugin marketplace add XuebinMa/agent-guard` resolves** — requires
      `main` pushed to origin. Pushed 2026-05-30 (origin/main @ cb3ba93). Re-verify
      it actually adds in a clean Claude Code before posting.
- [ ] **`cargo install` path verified on a clean machine** — the binary install is
      the one hard dependency (Rust toolchain). Confirm the documented command
      builds `guard-hook` from a fresh environment.
- [ ] **Lead with the stopped tool call, not the architecture** (Launch Kit rule).
- [ ] **No "complete agent security" / "fixes #33106" claims** (see S8-3).
- [ ] User has explicitly approved posting, per channel.

If the npm package is not published, every draft below switches to the
**marketplace-first** variant (provided inline) — do not post the `npx` variant.

---

## Positioning for this wave

The new thing in Sprint 8 is **distribution**: agent-guard is now a Claude Code
plugin you add in one line, not a repo you clone and wire by hand. The hook gates
the built-in tools where PreToolUse `deny` is actually enforced
(`Bash`, `Write`, `Edit`, `WebFetch`), writes a local outbound policy, and is
fail-open + idempotent.

One sentence:

> agent-guard is now a Claude Code plugin: one line to put a real
> approve/deny boundary in front of your coding agent's `git push`, file writes,
> and outbound HTTP — local-first, auditable, fail-open.

---

## X (Twitter)

### Variant 1 — marketplace-first (safe to post once marketplace verified)

```text
Your AI coding agent can `git push`, write files, and hit the network on its own.

agent-guard is now a Claude Code plugin — one line to put an approve/deny gate in front of those calls:

/plugin marketplace add XuebinMa/agent-guard
/plugin install agent-guard@agent-guard

Local-first. Fail-open. Signed audit trail.
```

### Variant 2 — npx-first (ONLY after the npm package is published)

```text
One command to gate your Claude Code agent's risky tool calls:

npx agent-guard-plugin init

Now `git push`, file writes, and outbound HTTP go through an explicit
approve/deny boundary before they happen. Local-first, auditable, idempotent.
```

Reply-bait follow-up (either variant):

```text
Honest scope: it gates the built-in tools where PreToolUse deny is enforced
today (Bash/Write/Edit/WebFetch). MCP tools aren't gated by the hook — route
those through the SDK. No "total security" claims; it's a decision boundary.
```

---

## Hacker News

**Title options (pick one):**

- `Show HN: agent-guard – a Claude Code plugin that gates your agent's risky tool calls`
- `Show HN: One-line approve/deny boundary for AI coding agents (Claude Code plugin)`

**Body:**

```text
agent-guard sits between your coding agent's tool intent and real execution. It
evaluates each call against a policy and either allows it, denies it, or asks you
— before the side effect happens.

As of this week it's a Claude Code plugin, so setup is one line instead of a
manual hook wire-up:

    /plugin marketplace add XuebinMa/agent-guard
    /plugin install agent-guard@agent-guard

(There's also `cargo install --path crates/guard-hook` from a checkout, and an
`npx agent-guard-plugin init` flow — see the repo for which fits you.)

What it gates today: the built-in Claude Code tools where PreToolUse deny is
actually enforced — Bash, Write, Edit, WebFetch. It ships an outbound policy that
treats `git push`, `npm publish`, `docker push`, `gh release`, and non-local HTTP
mutations as decision points. The hook is fail-open (a broken guard never blocks
your session) and idempotent (re-running init won't duplicate config).

Honest limitations, up front:
- MCP tools are NOT gated by the hook — Claude Code doesn't currently enforce
  PreToolUse deny for MCP calls (anthropics/claude-code#33106). For those, route
  intents through the Guard SDK, which enforces independently of the hook.
- It's a decision boundary, not a sandbox by default. OS-level sandboxing
  (seccomp / Seatbelt / Job Objects) is opt-in per platform and partial — the
  support matrix marks what's real.
- Single maintainer, 0.2.0-rc1. The signing/receipt/audit machinery is built but
  young.

It's Rust (7-crate workspace) with Python and Node bindings. Every decision can
emit an Ed25519-signed execution receipt for an auditable trail.

Repo: https://github.com/XuebinMa/agent-guard
3-minute proof: <link to three-minute-proof.md>

I'd genuinely like to hear where this boundary is in the wrong place — too
coarse, too noisy, or missing the tool category that actually scares you.
```

> HN note: the title says "Show HN" so the body must be buildable/runnable today.
> Do NOT post the `npx` line in the body unless the package is published — replace
> with the marketplace + cargo lines only.

---

## Reddit

Target subs: r/LocalLLaMA, r/ClaudeAI, r/ExperiencedDevs (pick by fit; read each
sub's self-promo rules first — several require a flair or limit promo frequency).

**Title:**

```text
I made a Claude Code plugin that gates your agent's git push / file writes / outbound HTTP (open source, local-first)
```

**Body:**

```text
I kept getting nervous about coding agents running with broad tool access — the
risky moment isn't the prompt, it's when the tool call actually reaches your
machine. So I built agent-guard: a policy boundary that checks each tool call and
allows / denies / asks before it executes.

It's now a Claude Code plugin:

    /plugin marketplace add XuebinMa/agent-guard
    /plugin install agent-guard@agent-guard

What it does:
- gates built-in tools where PreToolUse deny is enforced (Bash, Write, Edit,
  WebFetch)
- ships an outbound policy: git push / npm publish / docker push / gh release /
  non-local HTTP become explicit decisions
- fail-open (a broken guard never blocks you) and idempotent setup
- optional Ed25519-signed receipts for an audit trail

What it does NOT do (so nobody's surprised):
- it does not gate MCP tools via the hook — Claude Code doesn't currently enforce
  PreToolUse deny for MCP (anthropics/claude-code#33106); use the SDK path for those
- it's a decision boundary first; OS sandboxing is opt-in and partial
- solo maintainer, early (0.2.0-rc1)

Repo + 3-minute proof in the comments. Feedback on where the gate is wrong is the
thing I actually want.
```

---

## Comment-reply bank (reuse Launch Kit §7, plus these)

**"Doesn't Claude Code already ask permission?"**

> It does, per session, and people turn it off (`--dangerously-skip-permissions`)
> when the prompts get noisy. agent-guard makes the boundary a *policy* you write
> once — so the high-risk categories (push, publish, outbound mutation) get a
> consistent gate instead of fatigue-clicking allow.

**"What about MCP tools?"**

> The hook doesn't gate those — Claude Code doesn't enforce PreToolUse deny for
> MCP right now (anthropics/claude-code#33106). I don't pretend otherwise; for MCP
> intents you route through the Guard SDK, which enforces independent of the hook.

**"Is this a sandbox?"**

> Not by default — it's a decision boundary. OS-level sandboxing (seccomp /
> Seatbelt / Windows Job Objects) is opt-in and partial; the support matrix is
> honest about what's wired vs not.

**"Why Rust?"**

> The control point sits in the hot path of every tool call and signs receipts —
> it needs to be fast and dependency-light. There are Python and Node bindings if
> you don't want to touch Rust.

---

## Recommended posting sequence (after gating checklist passes)

1. Push verified + marketplace add confirmed in a clean Claude Code.
2. X (marketplace variant) — lowest stakes, fastest signal.
3. Reddit (one sub, the best-fit one) — read its self-promo rule first.
4. Show HN — only when the demo + install are reproducible on a clean machine,
   and ideally when you can babysit comments for the first few hours.
5. Hold the `npx` variants until the npm package is published; then update X +
   pin a follow-up.

## Success signal to watch (from the plan, ~4 weeks out)

- GitHub stars ≥ 50, ≥ 1 external PR, someone installs via the marketplace.
- Failure signal: < 20 stars / 0 external issue 4 weeks post-Sprint-8 → stop and
  return to diagnosis rather than pour in more.
