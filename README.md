# agent-guard

> The execution control layer for agent side effects.
> When an agent is about to do something real, `agent-guard` decides whether to execute it, deny it, ask for approval, or hand it back to the host.

[![Version](https://img.shields.io/badge/Version-0.2.0--rc1-blue.svg)]()
[![Focus](https://img.shields.io/badge/Focus-Execution%20Control-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)]()

`agent-guard` is for AI application and agent developers who need a real execution boundary before tool calls turn into shell commands, file mutations, or other side effects. It sits between agent intent and execution so risky actions do not rely only on prompts, regexes, or ad hoc handler code.

Today, the clearest short-term wedge is side-effect execution control across a very small set of high-risk actions:

- shell / terminal
- file write
- outbound mutation HTTP
- one runtime decision surface for `execute | deny | ask_for_approval | handoff`

That narrow wedge is the adoption point, not the final scope. The project can grow into broader side-effect control over time, but the reason to use it now is simple: it gives your agent a real execution decision point where side effects become real.

---

## Latest Release

- **Prerelease**: [`v0.2.0-rc1`](https://github.com/XuebinMa/agent-guard/releases/tag/v0.2.0-rc1)
- **Announcement**: [GitHub Discussions #1](https://github.com/XuebinMa/agent-guard/discussions/1)

---

## See The Wedge

If you only try one thing, run the side-effect wedge demo:

```bash
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:wedge --prefix crates/agent-guard-node
```

What you should see:

```text
=== agent-guard side-effect wedge ===

[1] shell decision: execute
[2] file decision: execute
[3] http decision: execute
[4] remote publish decision: ask_for_approval
```

That path is documented in [Side-Effect Wedge Demo](docs/guides/getting-started/side-effect-wedge-demo.md).

If you want the fastest shell-only proof instead, use [Three-Minute Proof](docs/guides/getting-started/three-minute-proof.md).

---

## What It Does

The core runtime decision now looks like this:

```text
agent action
  -> agent-guard
  -> execute | deny | ask_for_approval | handoff
  -> optional guard-owned execution
  -> audit outcome
```

This is the difference between:

- hoping the model behaves
- and putting an explicit execution control layer in front of side effects

Today, the runtime can already own execution for:

- shell / terminal
- file write
- outbound mutation HTTP

---

## Why Developers Adopt It

- **Real boundary, not prompt-only safety**: risky tool calls hit a decision point before execution.
- **Small integration surface**: wrap existing LangChain-style tools or OpenAI-style handlers instead of rewriting your runtime.
- **Incremental rollout**: start with the raw runtime APIs for the highest-risk side effects, then layer adapters on top where they fit.
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

- shell / terminal, file write, and outbound mutation HTTP are the main proof surfaces
- Node is the fastest adoption path
- normalized runtime decisions, approval flows, and auditable outcomes are available now

What to understand before integrating:

- the raw runtime APIs now expose `execute | deny | ask_for_approval | handoff`
- adapter `enforce` is still strongest on shell-like execution paths today
- broader capability coverage is intentionally narrow, not generic
- broader policy workflow and control-plane ideas are future expansion paths, not the phase-one hook

---

## Fastest Paths

- [Node Quickstart](crates/agent-guard-node/examples/quickstart/README.md): shortest end-to-end path for a new developer
- [Side-Effect Wedge Demo](docs/guides/getting-started/side-effect-wedge-demo.md): best current proof of the multi-side-effect runtime
- [Secure Shell Tools](docs/guides/getting-started/secure-shell-tools.md): best first integration when shell is the risk
- [Check vs Enforce](docs/guides/getting-started/check-vs-enforce.md): when to keep your handler vs when to move execution into `agent-guard`
- [Framework Support Matrix](docs/framework-support-matrix.md): what is supported today across Node, Python, and Rust
- [User Manual](docs/guides/getting-started/user-manual.md): install, policy basics, and SDK integration

Additional references:

- [Latest Release](https://github.com/XuebinMa/agent-guard/releases/tag/v0.2.0-rc1)
- [Join the Discussion](https://github.com/XuebinMa/agent-guard/discussions/1)
- [Deployment Guide](docs/guides/operations/deployment-guide.md)
- [Documentation Archive](docs/archive/README.md)
- [Documentation Hub](docs/README.md)

---

## Framework Entry Points

- **Node**: strongest current adoption surface, with wrappers for LangChain-style tools and OpenAI-style handlers
- **Python**: wrapper surface is available, with broader runtime semantics not yet brought to parity
- **Rust SDK**: most direct integration path for hosts that want explicit control over side-effect decisioning and execution

---

## Contributing

We welcome security research and contributions. Please see `CONTRIBUTING.md` for details.

*Copyright © 2026 agent-guard team. Distributed under the MIT License.*
