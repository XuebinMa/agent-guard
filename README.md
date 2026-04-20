# agent-guard

> The execution control layer for agent side effects.
> When an agent is about to do something real, `agent-guard` decides whether to allow it, block it, ask for approval, or take over execution.

[![Version](https://img.shields.io/badge/Version-0.2.0--rc1-blue.svg)]()
[![Focus](https://img.shields.io/badge/Focus-Execution%20Control-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)]()

`agent-guard` is for AI application and agent developers who need a real execution boundary before tool calls turn into shell commands, file mutations, or other side effects. It sits between agent intent and execution so risky actions do not rely only on prompts, regexes, or ad hoc handler code.

Today, the clearest proof point is shell / Bash execution:

- gate risky commands before they reach the real shell
- deny or ask for approval on dangerous requests
- move the highest-risk execution path into the SDK's controlled execution flow
- keep audit records of what was allowed, blocked, or executed

That shell-first story is the adoption wedge, not the final scope. The project can grow into broader side-effect control over time, but the reason to use it now is simple: it gives your agent a real execution decision point where it matters most.

---

## Latest Release

- **Prerelease**: [`v0.2.0-rc1`](https://github.com/XuebinMa/agent-guard/releases/tag/v0.2.0-rc1)
- **Announcement**: [GitHub Discussions #1](https://github.com/XuebinMa/agent-guard/discussions/1)

---

## See The Value In 3 Minutes

If you only try one thing, run the proof demo:

```bash
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:proof --prefix crates/agent-guard-node
```

What you should see:

```text
=== Safe Command ===
without guard: UNSAFE_HANDLER_WOULD_RUN:echo hello from attack demo
with guard: allowed

=== Approval Required Command ===
without guard: UNSAFE_HANDLER_WOULD_RUN:git push origin main
with guard: blocked

=== Destructive Command ===
without guard: UNSAFE_HANDLER_WOULD_RUN:rm -rf /
with guard: blocked
```

That path is documented in [Three-Minute Proof](docs/guides/getting-started/three-minute-proof.md).

![agent-guard proof demo screenshot](docs/assets/demo-proof-terminal.svg)

---

## What It Does

The core runtime decision looks like this:

```text
agent tool call
  -> agent-guard
  -> allow | deny | ask for approval | execute through guarded path
  -> optional sandbox-backed execution
  -> audit outcome
```

This is the difference between:

- hoping the model behaves
- and putting an explicit execution control layer in front of side effects

For shell tools, that boundary is strongest today because `enforce` can move execution into the SDK path instead of leaving the final shell call in your original handler.

---

## Why Developers Adopt It

- **Real boundary, not prompt-only safety**: risky tool calls hit a decision point before execution.
- **Small integration surface**: wrap existing LangChain-style tools or OpenAI-style handlers instead of rewriting your runtime.
- **Incremental rollout**: start with shell tools in `enforce`, keep lower-risk tools in `check`, and expand from there.
- **Auditable outcomes**: keep receipts and logs as support for trust and review, without making enterprise workflow the first thing you have to buy into.

---

## Best Fit Right Now

- code agents or shell-enabled agents
- AI applications with high-risk tool calls
- teams that need a pre-execution decision layer before real side effects happen

## Not The First Thing To Reach For

- chat-only assistants with no tool execution
- teams looking for a full orchestration framework
- teams expecting a finished enterprise control plane on day one

---

## Current Scope

What is strong today:

- shell / Bash protection is the main proof point
- Node is the fastest adoption path
- policy decisions, approval flows, and auditable outcomes are available now

What to understand before integrating:

- `enforce` is strongest on shell-like execution paths
- non-shell tools are primarily a `check`-first story today unless your host adds its own execution boundary
- broader policy workflow and control-plane ideas are future expansion paths, not the phase-one hook

---

## Fastest Paths

- [Node Quickstart](crates/agent-guard-node/examples/quickstart/README.md): shortest end-to-end path for a new developer
- [Secure Shell Tools](docs/guides/getting-started/secure-shell-tools.md): best first integration when shell is the risk
- [Check vs Enforce](docs/guides/getting-started/check-vs-enforce.md): when to keep your handler vs when to move execution into `agent-guard`
- [Framework Support Matrix](docs/framework-support-matrix.md): what is supported today across Node, Python, and Rust
- [User Manual](docs/guides/getting-started/user-manual.md): install, policy basics, and SDK integration

Additional references:

- [Latest Release](https://github.com/XuebinMa/agent-guard/releases/tag/v0.2.0-rc1)
- [Join the Discussion](https://github.com/XuebinMa/agent-guard/discussions/1)
- [Trust Tooling](docs/guides/getting-started/trust-tooling.md)
- [Architecture & Vision](docs/architecture-and-vision.md)
- [Documentation Hub](docs/README.md)

---

## Framework Entry Points

- **Node**: strongest current adoption surface, with wrappers for LangChain-style tools and OpenAI-style handlers
- **Python**: wrapper surface is available, with shell enforcement still centered on the Bash path
- **Rust SDK**: most direct integration path for hosts that want explicit control over the execution pipeline

---

## Contributing

We welcome security research and contributions. Please see `CONTRIBUTING.md` for details.

*Copyright © 2026 agent-guard team. Distributed under the MIT License.*
