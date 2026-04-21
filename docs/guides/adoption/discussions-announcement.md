# GitHub Discussions Announcement

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Ready To Post |
| **Audience** | Maintainers, Community, First-Time Evaluators |
| **Version** | 1.0 |
| **Last Reviewed** | 2026-04-14 |
| **Related Docs** | [Release Announcement Template](release-announcement.md), [Social Post Templates](social-posts.md), [FAQ For New Users](faq-for-new-users.md), [Three-Minute Proof](../getting-started/three-minute-proof.md) |

---

This is a channel-specific campaign asset. Use it when you are ready to post on GitHub Discussions, not as a primary explanation of the project itself.

---

This is a finished GitHub Discussions announcement draft. You can post it as-is or make light edits for tone.

Recommended category:

- `Announcements`

Recommended title:

- `agent-guard` v0.2.0-rc1: a safer execution boundary for AI tool calls

---

## Final Draft

```md
# `agent-guard` v0.2.0-rc1: a safer execution boundary for AI tool calls

AI agents that can call tools, especially shell-like tools, should not rely on prompt trust alone.

That is the problem `agent-guard` is focused on solving.

The project puts a policy gate and OS sandbox in front of AI tool calls so risky commands do not silently flow into execution.

## Why this matters

A lot of current agent security still depends on some combination of:

- prompt instructions
- ad hoc command validation
- framework-specific wrapper logic

Those things can help, but they are not the same as a reusable decision boundary at the tool layer.

`agent-guard` is meant to make that boundary explicit.

## The fastest way to evaluate it

Run the proof demo:

```bash
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:proof --prefix crates/agent-guard-node
```

What you should see:

- a safe command that is allowed
- a risky command such as `git push origin main` that is blocked or moved to approval
- a destructive command such as `rm -rf /` that is stopped before execution

This is the core product story:

Without a guard, the tool call flows directly into execution.  
With `agent-guard`, the same call must pass a decision boundary first.

## What is available today

- Node high-level adapters for LangChain-style tools and OpenAI-style handlers
- Rust SDK integration path
- Python LangChain-oriented binding
- proof demo, quickstart, support matrix, and visual demo assets
- release, social, and onboarding material for easier adoption

## Best-fit users right now

- engineers building code agents with shell access
- teams exposing tool-calling runtimes to LLMs
- platform or security teams that need auditable tool execution

## Start here

- [Three-Minute Proof](https://github.com/XuebinMa/agent-guard/blob/main/docs/guides/getting-started/three-minute-proof.md)
- [Node Quickstart](https://github.com/XuebinMa/agent-guard/blob/main/crates/agent-guard-node/examples/quickstart/README.md)
- [Framework Support Matrix](https://github.com/XuebinMa/agent-guard/blob/main/docs/framework-support-matrix.md)
- [Launch Kit](https://github.com/XuebinMa/agent-guard/blob/main/docs/guides/adoption/launch-kit.md)
- [Release](https://github.com/XuebinMa/agent-guard/releases/tag/v0.2.0-rc1)

## Discussion

If you are building a code agent or tool-calling runtime, I would especially love feedback on:

1. Where is your current shell or tool boundary?
2. Are you relying mostly on prompts, custom validation, or host-level isolation today?
3. Which tool category feels riskiest in your own stack?
4. What would make this easier to try in a real project?
```

---

## Suggested Add-On

If the GitHub Discussions editor supports it cleanly, place this image near the top of the post:

- [demo-proof-terminal.svg](../../assets/demo-proof-terminal.svg)

If you prefer a shorter version, use [Social Post Templates](social-posts.md) as the source and keep only the opening, proof demo, and three links.
