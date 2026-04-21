# Social Post Templates

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Ready To Use |
| **Audience** | Maintainers, DevRel, Community Posts |
| **Version** | 1.0 |
| **Last Reviewed** | 2026-04-14 |
| **Related Docs** | [Launch Kit](launch-kit.md), [Release Announcement Template](release-announcement.md), [Three-Minute Proof](../getting-started/three-minute-proof.md) |

---

This page gives you reusable post drafts for X, GitHub Discussions, Reddit, LinkedIn, and issue comments.

The goal is to keep the message consistent:

**High-risk agent side effects should not rely on prompt trust alone.**

---

## 1. Very Short Version

Use this for X or short project updates.

```text
Shell-enabled agents should not rely on “please be safe” prompts.

`agent-guard` puts a real execution boundary in front of shell commands and other high-risk side effects.

Fastest proof:
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:proof --prefix crates/agent-guard-node
```

---

## 2. Medium Version

Use this for GitHub Discussions, Discord, Slack, or a slightly longer X thread opener.

```text
One practical way to improve agent security is to move control from prompt text to the tool boundary.

We have been building `agent-guard` for that exact problem.

It puts a real execution boundary in front of shell commands and other high-risk side effects, starting with the shell-first path.

The quickest way to see the value is the proof demo:
- safe command: allowed
- git push: blocked or approval-required
- destructive command: stopped before execution

Try it:
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:proof --prefix crates/agent-guard-node

Docs:
- Three-Minute Proof: ../getting-started/three-minute-proof.md
- Node Quickstart: ../../../crates/agent-guard-node/examples/quickstart/README.md
- Framework Support Matrix: ../../framework-support-matrix.md
```

---

## 3. Long Version

Use this for Reddit, LinkedIn, GitHub Discussions, or a blog-style project update.

```text
Most AI agent stacks still rely too heavily on a fragile assumption: if the prompt says “be safe,” the tool call will probably be safe too.

That breaks down quickly when the runtime can call shell tools, file-capable tools, or other high-risk handlers.

We built `agent-guard` to put a real decision boundary in front of shell commands and other risky side effects.

What it does:
- checks tool calls against policy before execution
- can route execution through an OS sandbox path
- supports auditable outcomes and deeper verification workflows

What makes it easy to evaluate:
- a 3-minute proof demo
- a Node quickstart
- documented support status for framework adapters

If you want the shortest proof, run:

npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:proof --prefix crates/agent-guard-node

That demo shows the exact story we care about:
- safe command still works
- risky command no longer silently executes
- destructive command is stopped before execution

If you are building code agents with `bash` or exposing tool-calling runtimes to LLMs, this is the part of the stack we think deserves a stronger boundary.
```

---

## 4. Screenshot Caption

Use this when posting the proof demo image.

```text
This is the whole story in one screenshot:

without guard: the shell-like handler would accept the command
with guard: the risky tool call is checked before execution

That is the boundary `agent-guard` is trying to make explicit.
```

---

## 5. Discussion Starter Questions

Use these when you want replies instead of just impressions:

- If you are building a code agent, where is your current shell/tool boundary?
- Are you relying on prompt instructions, custom validation, or host-level isolation today?
- Which tool category feels riskiest in your own agent runtime?

---

## 6. Link Set

When a platform allows multiple links, use this order:

1. [Three-Minute Proof](../getting-started/three-minute-proof.md)
2. [Node Quickstart](../../../crates/agent-guard-node/examples/quickstart/README.md)
3. [Framework Support Matrix](../../framework-support-matrix.md)

If you can only share one link, use:

- [Three-Minute Proof](../getting-started/three-minute-proof.md)
