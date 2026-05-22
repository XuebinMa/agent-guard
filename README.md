# agent-guard

> Outbound change control for AI coding agents — action and content.
> Your agent writes code and runs tests freely; the moment it tries to push, publish, deploy, or send a secret out, `agent-guard` is the gate.

[![Version](https://img.shields.io/badge/Version-0.2.0--rc1-blue.svg)]()
[![Focus](https://img.shields.io/badge/Focus-Outbound%20Control-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)]()
[![MSRV](https://img.shields.io/badge/MSRV-1.79-orange.svg)]()

`agent-guard` is for developers running AI coding agents — Claude Code, Cursor, Codex CLI, Aider — who don't want the next `git push --force` to be the agent's idea, and don't want a stray `.env` quietly making it into the model's context.

Two layers of outbound control, one decision surface:

- **Action layer** (today): gate `git push`, `npm publish`, `docker push`, `gh release create`, non-local HTTP mutations, `rm -rf` — before they become real
- **Content layer** (roadmap): detect credentials and PII in tool inputs and outputs before they reach the LLM provider or external API
- **Audit layer**: every decision signed with Ed25519 — tamper-evident receipts ready for EU AI Act articles 28-31 evidence

Best fit: solo and small-team devs running coding agents in real workflows. **Local-first by design** — no cloud, no telemetry, no data leaves your machine.

Why now: EU AI Act enforcement begins 2026-08-02. Claude Code's PreToolUse hook has known gaps with MCP tools (#33106). DNS-tunnel credential exfiltration exploits (CVE-2025-55284) are already in the wild. The cost of "the agent did something irreversible" is no longer hypothetical.

---

## Latest Release

- **Prerelease**: [`v0.2.0-rc1`](https://github.com/XuebinMa/agent-guard/releases/tag/v0.2.0-rc1)
- **Announcement**: [GitHub Discussions #1](https://github.com/XuebinMa/agent-guard/discussions/1)

## Verify Locally

If you are touching the repository itself, use the shared verification entrypoint:

```bash
./scripts/verify.sh full
```

Useful narrower paths:

- `./scripts/verify.sh rust`
- `./scripts/verify.sh lint`
- `./scripts/verify.sh python`
- `./scripts/verify.sh node`

The verification script uses temporary directories for Python build/test work so routine verification does not leave `venv_*` style residue in the repository root.

---

## Try The Preset First

The fastest adoption path is the zero-config outbound preset. It covers all five action-layer categories (code egress, package release, artifact egress, remote mutation, destructive shell) with sensible defaults, so you do not have to write your first rule.

```bash
cargo install --path crates/guard-hook   # one-time install of the Claude Code adapter
guard-hook check \
  --policy presets/coding-agent-outbound.yaml \
  --agent-id smoke-test < event.json
```

A real `git push` from the agent then surfaces as an `ask` decision; a `git push --force` is denied outright; a `cargo build` passes through with no friction. See [presets/README.md](presets/README.md) for adoption with the Rust SDK, Node binding, or Claude Code PreToolUse hook, and for the contributing guide on new presets.

For a runnable decision preview of the preset — an agent finishing a feature, then the gate firing on `git push` — use the bundled demo:

```bash
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:outbound --prefix crates/agent-guard-node
```

If you prefer a runnable end-to-end demo of the multi-side-effect runtime, the Node side-effect wedge is also wired up:

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

That path is documented in [Side-Effect Wedge Demo](docs/guides/getting-started/side-effect-wedge-demo.md). For the fastest shell-only proof, use [Three-Minute Proof](docs/guides/getting-started/three-minute-proof.md).

---

## What It Does

The core runtime decision now looks like this:

```text
agent action (outbound moment)
  -> agent-guard
  -> execute | deny | ask_for_approval | handoff
  -> optional guard-owned execution
  -> Ed25519-signed audit record
```

This is the difference between:

- hoping the model behaves
- and putting an explicit gate in front of every outbound action

Today, the runtime can already own execution for:

- shell / terminal
- file write
- outbound mutation HTTP

Together those three surfaces cover the action-layer categories the preset bundles (code egress, package release, artifact egress, remote mutation, destructive shell).

---

## Why Developers Adopt It

- **A real outbound boundary, not prompt-only safety**: `git push`, `npm publish`, `docker push`, `rm -rf`, `kubectl apply` all hit a decision point before they become real.
- **Zero-config preset**: a copy-able policy that covers the five action-layer categories on day one — no rule-writing required.
- **Small integration surface**: wrap existing LangChain-style tools or OpenAI-style handlers, or hook into Claude Code's PreToolUse via `guard-hook`. No runtime rewrite.
- **Tamper-evident audit**: every decision is Ed25519-signed, JSONL-formatted, and ready to map onto EU AI Act articles 28-31 without an enterprise control plane.

---

## Best Fit Right Now

- solo and small-team devs running Claude Code / Cursor / Codex CLI / Aider against real codebases
- shell-enabled coding agents that publish, push, deploy, or otherwise produce outbound effects
- teams that want a tamper-evident audit trail before the EU AI Act enforcement deadline

## Not The First Thing To Reach For

- chat-only assistants with no tool execution
- teams looking for a full orchestration framework
- teams expecting a finished enterprise control plane on day one

---

## Adjacent Layer: Loop Governance

`agent-guard` controls the **outbound side effect** on each tool call. It deliberately does not govern the surrounding autonomous loop — budget caps, verifier gates, retry admission, and JSONL run records are a different failure mode (a 47-retry overnight bill vs. a single rogue `git push`).

For that layer, see [MartinLoop](https://github.com/Keesan12/martin-loop): it wraps autonomous coding agents with budgets, verifier gates, and run records. The two layers compose — MartinLoop decides whether the next attempt is admitted; `agent-guard` decides whether the side effects inside that attempt are allowed to leave.

---

## Current Scope

What is strong today (action layer):

- the five outbound action categories — code egress, package release, artifact egress, remote mutation, destructive shell — are covered by a zero-config preset
- shell / terminal, file write, and outbound mutation HTTP are the underlying runtime proof surfaces
- normalized runtime decisions, approval flows, and Ed25519-signed audit records are available now
- the SDK already includes policy signing, execution receipts, metrics, anomaly detection, and SIEM export beyond the narrow wedge

What is roadmap (content layer):

- credentials / PII detection on tool inputs and outputs before they reach the LLM provider or external API
- HTTP method matching in policy (today the schema is URL-only; method-aware filtering goes host-side — see [presets/README.md](presets/README.md))
- distribution as a Claude Code plugin / ECC marketplace entry

What to understand before integrating:

- raw runtime APIs expose `execute | deny | ask_for_approval | handoff`
- adapter `enforce` is still strongest on shell-like execution paths today
- Bash has the deepest validator path; `read_file` / `write_file` normalize paths and fail closed on symlink escapes; HTTP policy matching is URL-centric (see roadmap)
- Python and Node bindings use the SDK's default sandbox selection in the current release; explicit backend selection is deferred until pilot demand surfaces
- broader capability coverage is intentionally narrow, not generic
- broader policy workflow and control-plane ideas are future expansion paths, not the phase-one hook

---

## Fastest Paths

- [Outbound preset](presets/README.md): the zero-config policy for coding-agent users — start here
- [Claude Code PreToolUse hook](docs/guides/operations/claude-code-hook.md): wire `guard-hook` into your live Claude Code session
- [Node Quickstart](crates/agent-guard-node/examples/quickstart/README.md): shortest programmatic path for a new developer
- [Side-Effect Wedge Demo](docs/guides/getting-started/side-effect-wedge-demo.md): runnable proof of the multi-side-effect runtime
- [Secure Shell Tools](docs/guides/getting-started/secure-shell-tools.md): first integration when shell is the dominant risk
- [Check vs Enforce](docs/guides/getting-started/check-vs-enforce.md): when to keep your handler vs when to move execution into `agent-guard`
- [Framework Support Matrix](docs/reference/framework-support-matrix.md): current Node / Python / Rust adoption surfaces
- [User Manual](docs/guides/getting-started/user-manual.md): install, policy basics, and SDK integration

Additional references:

- [Latest Release](https://github.com/XuebinMa/agent-guard/releases/tag/v0.2.0-rc1)
- [Join the Discussion](https://github.com/XuebinMa/agent-guard/discussions/1)
- [Deployment Guide](docs/guides/operations/deployment-guide.md)
- [Documentation Archive](docs/archive/README.md)
- [Documentation Hub](docs/README.md)

---

## Framework Entry Points

- **Claude Code**: the `guard-hook` PreToolUse adapter is the lowest-friction entry — point one `--policy` flag at the outbound preset
- **Node**: strongest programmatic surface, with wrappers for LangChain-style tools and OpenAI-style handlers
- **Python**: wrap_langchain_tool / wrap_openai_tool are available; a real-package validation script ships, automated CI version matrix is the remaining gap
- **Rust SDK**: most direct integration path for hosts that want explicit control over side-effect decisioning and execution

---

## Contributing

We welcome security research and contributions. Please see `CONTRIBUTING.md` for details.

*Copyright © 2026 agent-guard team. Distributed under the MIT License.*
