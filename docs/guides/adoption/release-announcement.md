# Release Announcement Template

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Ready To Adapt |
| **Audience** | Maintainers, Release Authors, DevRel |
| **Version** | 1.0 |
| **Last Reviewed** | 2026-04-14 |
| **Related Docs** | [Launch Kit](launch-kit.md), [Demo Asset Workflow](demo-asset-workflow.md), [Three-Minute Proof](../getting-started/three-minute-proof.md) |

---

This is a campaign asset for publishing releases or project updates. It is most useful after the core positioning and proof path are already clear.

---

This template is for GitHub Releases, project updates, and announcement posts that need to convert curiosity into a first run.

The job of this announcement is not to describe everything in the repository.

The job is to help a new reader understand:

- what problem `agent-guard` solves
- why it matters now
- what to run first

---

## 1. Recommended Title

Pick a title with a clear value statement.

Good options:

- `agent-guard`: a safer execution boundary for AI tool calls
- New in `agent-guard`: proof-driven shell tool protection for AI agents
- `agent-guard` update: run a 3-minute proof of blocked risky tool calls

Avoid titles that are too internal, such as:

- release train summaries
- milestone numbers without context
- feature bundles with no user-facing outcome

---

## 2. Short Announcement Version

Use this when you want a compact GitHub release or project update.

```md
## Why this project exists

AI agents that can call tools, especially shell-like tools, should not rely on prompt trust alone.

`agent-guard` puts a policy gate and OS sandbox in front of AI tool calls so risky commands do not silently flow into execution.

## What you can verify right now

Run the proof demo:

```bash
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:proof --prefix crates/agent-guard-node
```

What you will see:

- a safe command that is allowed
- a risky command that is blocked or moved to approval
- a destructive command that is stopped before execution

## Why this is useful

- protect shell and other high-risk tools at the tool boundary
- add guardrails to LangChain-style tools and OpenAI-style handlers
- move from `check` to `enforce` without rewriting your runtime
- keep an auditable path for what was allowed or blocked

## Start here

- [Three-Minute Proof](../getting-started/three-minute-proof.md)
- [Node Quickstart](../../../crates/agent-guard-node/examples/quickstart/README.md)
- [Framework Support Matrix](../../framework-support-matrix.md)
```

---

## 3. Full Announcement Version

Use this when you want a more complete public post.

```md
## `agent-guard`: a safer execution boundary for AI tool calls

Most AI agent demos still rely on a fragile assumption: if the prompt says “be safe,” the tool call will probably be safe too.

That assumption breaks down quickly for shell tools, file-capable tools, and high-risk runtimes.

`agent-guard` is built to move control from prompt trust to the tool boundary. It places a policy gate in front of tool calls and can execute them through an OS sandbox path, with auditability and proof-oriented workflows available for teams that need deeper trust.

## The fastest way to understand it

Run the proof demo:

```bash
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:proof --prefix crates/agent-guard-node
```

This shows:

- a safe command still works
- `git push origin main` no longer silently executes
- `rm -rf /` is stopped before reaching the host execution path

That is the key product story:

Without a guard, the tool call flows directly into execution.  
With `agent-guard`, the same call must pass a decision boundary first.

## What is available today

- Node high-level adapters for LangChain-style tools and OpenAI-style handlers
- Rust SDK integration path
- Python LangChain-oriented binding
- a proof demo, quickstart, support matrix, and visual demo assets

## Best-fit users right now

- engineers building code agents with shell access
- teams exposing tool-calling runtimes to LLMs
- platform or security teams that need auditability around tool execution

## Start here

- [Three-Minute Proof](../getting-started/three-minute-proof.md)
- [Node Quickstart](../../../crates/agent-guard-node/examples/quickstart/README.md)
- [Framework Support Matrix](../../framework-support-matrix.md)
- [Launch Kit](launch-kit.md)
```

---

## 4. What To Emphasize

Keep repeating the same few points:

- shell tools are the strongest current wedge
- the tool boundary matters more than prompt intentions
- the project is already runnable, not just conceptual
- the fastest proof is short and copyable

---

## 5. What Not To Lead With

Do not lead with:

- every platform nuance
- every roadmap phase
- low-level implementation details
- broad claims that all agent security is now solved

The release should create clarity, not cognitive overload.
