# agent-guard

> Exact outbound authorization for AI coding agents, starting with `git push`.
> Your agent writes code and runs tests freely; agent-guard makes the outbound
> intent visible and gives the host a decision before code leaves the machine.

[![Version](https://img.shields.io/badge/Version-0.2.1-blue.svg)]()
[![Focus](https://img.shields.io/badge/Focus-Outbound%20Control-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)]()
[![MSRV](https://img.shields.io/badge/MSRV-1.79-orange.svg)]()

`agent-guard` is for developers running AI coding agents — Claude Code, Cursor,
Codex CLI, Aider — who want a narrow, inspectable control at the point where
local code becomes a remote Git change.

Two layers of outbound control, one decision surface:

- **Action layer** (today): parse recognized Git push forms, conservatively flag
  embedded Git argv candidates, and evaluate shell, file-write, and HTTP tool
  calls against policy
- **Content layer** (experimental, opt-in): detect credentials and PII in tool inputs and outputs before they reach the LLM provider or external API
- **Evidence layer**: JSONL records for decisions; optional Ed25519-signed
  receipts only when the Guard owns execution and a signing key is configured

Best fit: solo and small-team devs running coding agents in real workflows.
**Local-first by default** — network export occurs only when the host explicitly
configures an outbound action or SIEM destination.

Why now: EU AI Act enforcement begins 2026-08-02. Claude Code's PreToolUse hook has known gaps with MCP tools (#33106). DNS-tunnel credential exfiltration exploits (CVE-2025-55284) are already in the wild. The cost of "the agent did something irreversible" is no longer hypothetical.

---

## Install

The Rust crates are on crates.io as of `0.2.0`:

```bash
cargo install guard-hook --locked
cargo install agent-guard-cli --locked
cargo install guard-verify --locked
```

As a Rust library:

```toml
[dependencies]
agent-guard-sdk = "0.2"
```

The Python and Node distributions are not published yet — the `0.2.0` release
run reached crates.io but stalled before them. Until `0.2.1` lands, install
them from a checkout:

```bash
python -m pip install ./crates/agent-guard-python   # imports as `agent_guard`
```

```bash
npm ci --prefix crates/agent-guard-node && npm run build --prefix crates/agent-guard-node
```

The unversioned `npx agent-guard-plugin` command still resolves to the older
`0.2.0-rc1` package, not this source tree.

## Release Status

- **Source version**: `v0.2.1` (crates.io only; PyPI and npm land with this release)
- **Latest published release**: [`v0.2.0`](https://github.com/XuebinMa/agent-guard/releases/tag/v0.2.0)
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
cargo install --path crates/guard-hook --locked
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
  -> optional Ed25519-signed execution receipt
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

- **One narrow outbound decision**: recognized direct `git push` spellings,
  plumbing-level `git send-pack` calls, and explicitly modeled wrappers are
  normalized before policy matching, including repository selectors,
  destructive flags, and force/delete refspec shorthand. Unknown outer
  commands containing adjacent standalone Git argv tokens are governed by a
  conservative, explicitly unverified check so they cannot weaken that
  decision.
- **Zero-config preset**: a copy-able policy that covers the five action-layer categories on day one — no rule-writing required.
- **Small integration surface**: wrap existing LangChain-style tools or OpenAI-style handlers, or hook into Claude Code's PreToolUse via `guard-hook`. No runtime rewrite.
- **Truthful evidence**: decisions are recorded as JSONL; executions can carry
  a signed receipt when the Guard owns the action and has an explicit key.

---

## Best Fit Right Now

- solo and small-team devs running Claude Code / Cursor / Codex CLI / Aider against real codebases
- shell-enabled coding agents that publish, push, deploy, or otherwise produce outbound effects
- teams that want a local forensic decision trail and optional signed execution receipts

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

- recognized direct Git push entry points and explicitly modeled wrappers are
  normalized into one policy decision; force, mirror, delete, and destructive
  refspec forms cannot fall back to a weaker raw string match
- adjacent standalone Git argv candidates under an unknown outer command are
  conservatively governed at the same decision strength and labeled as
  unverified; argv inspection cannot establish whether an arbitrary program
  will execute those arguments
- the broader zero-config preset covers five outbound action categories as an
  advisory policy, not as a credential-isolated containment boundary
- shell / terminal, file write, and outbound mutation HTTP are the underlying runtime proof surfaces
- HTTP policy rules are method-aware: a rule can carry a `method:` constraint (e.g. deny `POST`/`DELETE` to a host) instead of matching the URL alone
- normalized runtime decisions, a local single-user approval workflow, JSONL
  decision records, and optional Ed25519-signed execution receipts are available now
- the SDK already includes policy signing, execution receipts, metrics, anomaly detection, and SIEM export beyond the narrow wedge

What is experimental and opt-in (content layer):

- credential / PII detection on outbound content — `write_file` content and `http_request` body — behind the off-by-default `content` feature, with three enforcement modes (`block` / `mask` / `warn`). See [Content layer](#content-layer-experimental) below.
- the same detection on *input* text (prompts) before it reaches the LLM provider, via the top-level `input_content:` policy block and `Guard::check_content`

What is roadmap (primary product boundary):

- broker-enforced GitHub push for one repository and one branch: exact preview,
  short-lived one-use authorization, execution-time remote-state revalidation,
  Guard-held credentials, and a signed outcome receipt

What to understand before integrating:

- raw runtime APIs expose `execute | deny | ask_for_approval | handoff`
- adapter `enforce` is still strongest on shell-like execution paths today
- Bash has the deepest validator path; `read_file` / `write_file` normalize paths and fail closed on symlink escapes; HTTP policy rules can match on URL and method
- Python and Node bindings default to the SDK's platform sandbox selection; both also accept an explicit `backend` argument on `execute` / `run`, resolved truthfully (a backend that is not compiled in or not functional yields the `none` backend, never a false isolation claim)
- broader capability coverage is intentionally narrow, not generic
- broader policy workflow and control-plane ideas are future expansion paths, not the phase-one hook
- the advisory shell layer cannot prove arbitrary launcher semantics or stop a
  process that bypasses the hook; that class-level guarantee requires the
  planned credential-isolated broker

---

## Threat Coverage — OWASP Agentic Top 10

Where `agent-guard` sits on the OWASP Top 10 for Agentic Applications (ASI01–ASI10). It is an **execution-control** layer, so it is a *primary* control for the side-effect risks and a *containment* backstop for the autonomy ones — not a full-stack agentic-security platform.

- ✅ **Primary control**: **ASI02** Tool Misuse, **ASI05** Unexpected Code Execution
- 🟡 **Containment / accountability**: **ASI01** Goal Hijack, **ASI03** Privilege Abuse, **ASI08** Cascading Failures, **ASI09** Human-Agent Trust, **ASI10** Rogue Agents
- ⬜ **Out of scope** (by design): **ASI04** supply-chain / MCP scanning, **ASI06** memory poisoning, **ASI07** inter-agent comms

For Guard-owned executions configured with a signing key, Ed25519 receipts add
cryptographic provenance. Decision-only hooks do not create those receipts and
remain dependent on the host honoring the decision. Full mapping: [Framework Support Matrix §10](docs/reference/framework-support-matrix.md#10-threat-coverage--owasp-agentic-top-10).

---

## Content layer (experimental)

The action layer decides *whether* a call may leave. The content layer inspects
*what* leaves with it. It is **off by default** — opt in with the `content`
feature flag — and scans three surfaces: `write_file` content, `http_request`
body, and host-supplied *input* text (prompts) via `Guard::check_content`.

Add a `content` block to any tool rule:

```yaml
tools:
  http_request:
    mode: full_access
    content:
      mode: block          # block | mask | warn
      detect: [secrets, pii]   # optional; defaults to both
```

The three modes:

| Mode | Effect |
|------|--------|
| `block` | Deny the call when sensitive content is detected (`SENSITIVE_CONTENT_BLOCKED`). |
| `mask`  | Execute a redacted copy — each finding becomes `[REDACTED:<label>]` — and emit a `ContentFinding` audit record. |
| `warn`  | Execute unchanged, but emit a `ContentFinding` audit record. |

For *input* text the Guard never performs the downstream call, so the host
consumes the outcome directly — configure a top-level `input_content:` block
and call `check_content` on the text before forwarding it:

```yaml
input_content:
  mode: mask               # block | mask | warn
  detect: [secrets, pii]   # optional; defaults to both
```

```rust
use agent_guard_sdk::{Context, Guard};

let guard = Guard::from_yaml_file("policy.yaml")?;
let outcome = guard.check_content(prompt, &Context::default());
if outcome.blocked { /* refuse to forward the prompt */ }
let safe_prompt = outcome.masked_text.as_deref().unwrap_or(prompt);
```

Findings only ever expose the *kind* of data (e.g. `AWS Access Key`, `Email`),
never the raw matched substring — audit records carry labels and counts, not secrets.

Run the example:

```bash
cargo run -p agent-guard-sdk --example content_policy --features content
```

This is a spike-grade detector set (named patterns + entropy fallback for
secrets, regex + Luhn for PII), not a compliance-grade DLP engine. Treat it as a
safety net, not the primary control.

---

## Fastest Paths

- [Outbound preset](presets/README.md): the zero-config policy for coding-agent users — start here
- [Claude Code plugin](docs/guides/operations/claude-code-plugin.md): one-command install — `/plugin marketplace add XuebinMa/agent-guard`, then `/plugin install agent-guard@agent-guard`
- [Claude Code PreToolUse hook](docs/guides/operations/claude-code-hook.md): wire `guard-hook` into your live Claude Code session manually
- [Node Quickstart](crates/agent-guard-node/examples/quickstart/README.md): shortest programmatic path for a new developer
- [Side-Effect Wedge Demo](docs/guides/getting-started/side-effect-wedge-demo.md): runnable proof of the multi-side-effect runtime
- [Secure Shell Tools](docs/guides/getting-started/secure-shell-tools.md): first integration when shell is the dominant risk
- [Check vs Enforce](docs/guides/getting-started/check-vs-enforce.md): when to keep your handler vs when to move execution into `agent-guard`
- [Framework Support Matrix](docs/reference/framework-support-matrix.md): current Node / Python / Rust adoption surfaces
- [User Manual](docs/guides/getting-started/user-manual.md): install, policy basics, and SDK integration

Additional references:

- [Latest published release](https://github.com/XuebinMa/agent-guard/releases/tag/v0.2.0)
- [Join the Discussion](https://github.com/XuebinMa/agent-guard/discussions/1)
- [Deployment Guide](docs/guides/operations/deployment-guide.md)
- [Roadmap](ROADMAP.md): what's shipped, partial, and planned
- [Documentation Archive](docs/archive/README.md)
- [Documentation Hub](docs/README.md)

---

## Framework Entry Points

- **Claude Code**: the `guard-hook` PreToolUse adapter is the lowest-friction entry — point one `--policy` flag at the outbound preset
- **Node**: strongest programmatic surface, with wrappers for LangChain-style tools and OpenAI-style handlers
- **Python**: `wrap_langchain_tool` / `wrap_openai_tool` are available and the
  real-package CI matrix runs; the adapter surface remains beta
- **Rust SDK**: most direct integration path for hosts that want explicit control over side-effect decisioning and execution

---

## Contributing

We welcome security research and contributions. Please see `CONTRIBUTING.md` for details.

*Copyright © 2026 agent-guard team. Distributed under the MIT License.*
