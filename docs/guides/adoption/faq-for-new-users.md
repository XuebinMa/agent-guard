# FAQ For New Users

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Starter FAQ |
| **Audience** | Evaluators, First-Time Users, Community Readers |
| **Version** | 1.0 |
| **Last Reviewed** | 2026-04-14 |
| **Related Docs** | [Three-Minute Proof](../getting-started/three-minute-proof.md), [Secure Shell Tools](../getting-started/secure-shell-tools.md), [Framework Support Matrix](../../framework-support-matrix.md) |

---

This FAQ is meant for the first round of user questions, especially from people discovering the project through a post, screenshot, release note, or discussion thread.

---

## What problem does `agent-guard` solve?

It adds a policy and execution boundary in front of AI tool calls.

The strongest current use case is shell and other high-risk tools, where prompt instructions alone are not a reliable safety boundary.

---

## Why not just tell the model to be safe?

Because prompts are guidance, not durable enforcement.

They can help, but they are not a strong control point once a model can trigger a real tool.

`agent-guard` is designed for teams that want the tool call itself to pass through policy and, where available, OS-level restrictions.

---

## Why not just validate commands in application code?

Application-level validation is useful, but it tends to become fragmented, framework-specific, and hard to reason about across projects.

`agent-guard` tries to provide a reusable control point at the tool boundary instead of relying entirely on one-off wrapper logic.

---

## Who should use this first?

The best-fit early users are:

- engineers building code agents with `bash` or shell access
- teams exposing tool-calling runtimes to LLMs
- platform or security teams that need auditable tool execution

If your assistant never calls tools, this project will feel less urgent.

---

## What is the fastest way to see if it works?

Run the proof demo:

```bash
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:proof --prefix crates/agent-guard-node
```

Then read:

- [Three-Minute Proof](../getting-started/three-minute-proof.md)

---

## What should I expect from the proof demo?

You should see:

- one safe command allowed
- one risky command blocked or moved to approval
- one destructive command stopped before execution

The point is not to prove every security property in one step.

The point is to prove that the tool boundary is now explicit.

---

## Is this a full agent framework?

No.

`agent-guard` is a security and control layer for tool execution. It is not trying to replace your orchestration framework or become the whole agent runtime.

---

## Does this require me to rewrite my app?

Not necessarily.

The current Node path is intentionally adapter-oriented: wrap the tool boundary first, especially for LangChain-style tools and OpenAI-style handlers, then expand from there.

---

## Should I start with `check` or `enforce`?

Start with `check` when you want to understand policy behavior with lower rollout friction.

Move selected high-risk tools to `enforce` when you are ready for a stronger boundary.

More detail:

- [Check vs Enforce](../getting-started/check-vs-enforce.md)

---

## What should I read after the proof demo?

Use this order:

1. [Node Quickstart](../../../crates/agent-guard-node/examples/quickstart/README.md)
2. [Secure Shell Tools](../getting-started/secure-shell-tools.md)
3. [Framework Support Matrix](../../framework-support-matrix.md)

That path gives you:

- a runnable first step
- the strongest current use case
- an honest view of what is supported today
