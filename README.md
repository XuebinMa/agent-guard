# agent-guard

> Put a policy gate and OS sandbox in front of AI tool calls.
> Start with shell tools, high-risk actions, and agent runtimes that need a real execution boundary.

[![Version](https://img.shields.io/badge/Version-0.2.0--rc1-blue.svg)]()
[![Focus](https://img.shields.io/badge/Focus-Ecosystem%20%26%20Trust-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)]()

`agent-guard` is for teams building AI agents that can call tools, especially shell-like or other high-risk tools. Instead of relying on prompts like “please be safe,” it checks each tool call against policy and can execute it inside an OS sandbox.

If you are building:

- a code agent with `bash` or terminal access
- a tool-calling workflow with LangChain or OpenAI-style handlers
- an internal agent platform that needs auditability and receipts

this project is meant to give you a safer execution boundary.

---

## Why It Exists

Without a runtime guard, agent security usually depends on model behavior, prompt instructions, and ad hoc tool validation. That breaks down quickly for shell tools and other high-risk capabilities.

`agent-guard` changes that boundary:

- before tool execution: policy check, anomaly checks, audit hooks
- during execution: sandbox selection and restricted execution
- after execution: receipts, logs, and operator-visible diagnostics

This moves agent safety from “best effort” to “explicitly enforced at the tool boundary.”

---

## What You Can Do In 5 Minutes

Run a minimal Node quickstart that shows one safe command succeeding and one risky command being blocked:

```bash
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:quickstart --prefix crates/agent-guard-node
```

That quickstart lives in [examples/quickstart](/Users/xuebinma/Projects/agent-guard/crates/agent-guard-node/examples/quickstart/README.md).

If you want the shortest path to “does this actually stop risky tool calls?”, start there.

---

## Who Should Use It

### Best Fit Right Now

- engineers building code agents or shell-enabled agents
- teams adding safety around tool-calling runtimes
- platform or security teams that need receipts, policy control, and auditability

### Less Ideal As A First Use Case

- purely chat-only assistants with no tool execution
- projects looking for a full agent orchestration framework
- teams that only need prompt-layer filtering

---

## Key Value

- **Protect shell and high-risk tools**: Put policy checks in front of the most dangerous execution paths first.
- **Integrate without rewriting your app**: Wrap LangChain-style tools or OpenAI-style handlers at the tool boundary.
- **Move from `check` to `enforce` gradually**: Start with authorization-only gating, then enforce sandboxed execution for sensitive tools.
- **Keep proof, not just logs**: Generate signed receipts and auditable events for compliance-sensitive environments.
- **See the real host boundary**: Use transparency and doctor tooling to understand what your machine can actually enforce.

---

## Why This Is Different

Many agent stacks stop at “the model should not do that.”
`agent-guard` is built for “the tool call must still pass a policy and execution boundary.”

That is especially useful when:

- prompt injection reaches a tool-enabled agent
- a code agent gets overly broad shell access
- a platform team needs evidence of what was allowed, blocked, or sandboxed

---

## Framework Entry Points

- **Node**: high-level adapter layer for LangChain-style tools and OpenAI-style handlers, with real runtime validation against `@langchain/core` and `@openai/agents`
- **Python**: LangChain-oriented binding and examples
- **Rust SDK**: direct integration path for host applications and custom runtimes

---

## 📺 See it in Action

Run the built-in demos to see the security boundary in practice:

- **Happy Path**: `cargo run --example demo_happy_path` (Standard execution + cryptographic receipts)
- **Malicious Block**: `cargo run --example demo_malicious_block` (See the Deny Fuse lock out an attacker)
- **The Comparison**: `cargo run --example demo_comparison` (No Guard vs. Full Guard side-by-side)
- **Host Transparency**: `cargo run --example demo_transparency` (What can your host OS defend against?)
- **Doctor Report**: `cargo run -p agent-guard-sdk --example doctor` (Which backend will the SDK actually select, and why?)

---

## 📈 Reliability Signals

`agent-guard` is built for high-scale production environments. Our current release line has been [stress tested](docs/security-audit.md#2-findings--remediations):

- **Zero Resource Leaks**: Passed 60,000+ executions in 30s with zero handle or memory drift.
- **Concurrent Correctness**: Successfully handled 128+ concurrent agents with 100% decision accuracy.
- **Fail-Closed Design**: Blocks when the sandbox or environment cannot be safely initialized.

---

## 📖 Documentation & Usage

Ready to try or integrate it? Start with the path that matches your goal:

- 📘 **[User Manual](docs/guides/getting-started/user-manual.md)**: installation, policy basics, and SDK integration
- 🔐 **[Secure Shell Tools](docs/guides/getting-started/secure-shell-tools.md)**: the best first integration path for high-risk tool use
- ⚖️ **[Check vs Enforce](docs/guides/getting-started/check-vs-enforce.md)**: how to choose the right adapter mode
- 🚀 **[Node Quickstart](crates/agent-guard-node/examples/quickstart/README.md)**: fastest path to a first successful run
- 🏗️ **[Architecture & Vision](docs/architecture-and-vision.md)**: long-term roadmap and product direction
- 🧭 **[Framework Support Matrix](docs/framework-support-matrix.md)**: what is supported today across Rust, Node, Python, and framework adapters
- 🗺️ **[Capability Matrix](docs/capability-parity.md)**: platform-specific protection boundaries
- 📚 **[Documentation Hub](docs/README.md)**: full docs map
- 📈 **[Growth & Adoption Plan](docs/growth-and-adoption-plan.md)**: current go-to-market and adoption execution plan

---

## 🗺️ Roadmap

- [x] **Phase 1-4**: Core Engine, Linux Sandbox, Telemetry, Anomaly Detection.
- [x] **Phase 5-6**: Windows Low-IL, Unified Capability Model (UCM), Signed Receipts (Supported), SIEM.
- [x] **Phase 7**: Production Hardening, Cross-platform Parity, AppContainer Prototype.
- [x] **Phase 8**: RC Validation & Stress Testing.
- [~] **Phase 9 (Current)**: v0.3.0 Ecosystem & Trust: LangChain/OpenAI adapters, real framework validation, receipt verification tooling.
- [ ] **Phase 10 (Future)**: TPM-backed Remote Attestation, Linux Landlock Integration.

---

## 🤝 Contributing

We welcome security research and contributions. Please see `CONTRIBUTING.md` for details.

*Copyright © 2026 agent-guard team. Distributed under the MIT License.*
