# Framework Support Matrix

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Active Support Snapshot |
| **Audience** | Developers, Integrators |
| **Version** | 1.3 |
| **Last Reviewed** | 2026-06-04 |
| **Related Docs** | [README](../README.md), [Node README](../../crates/agent-guard-node/README.md), [Python README](../../crates/agent-guard-python/README.md) |

---

This matrix answers the practical adoption questions for the current execution-control surface:

- which integration surfaces are available today?
- how mature are they?
- what has been validated in the repository?
- what should a new user try first?

This is not the same as the OS sandbox matrix in [capability-parity.md](../concepts/capability-parity.md).  
That document describes platform enforcement boundaries.  
This document describes framework and binding readiness.  
For how `agent-guard` maps onto the OWASP Agentic Top 10 *threat* list — a coverage question, not a readiness question — see [§10](#10-threat-coverage--owasp-agentic-top-10).

It is intentionally narrower than a broad platform map. The goal is to help a developer decide where to start now, not to imply that every language and framework path is equally mature.

---

## 1. Summary Matrix

| Surface | Status | Validation Level | Best For | Notes |
| :--- | :--- | :--- | :--- | :--- |
| Rust SDK | ✅ Supported | Real workspace tests and examples | Host applications, custom runtimes | Most direct integration surface. |
| Node binding | ✅ Supported | Native smoke tests | Node services and wrappers | Stable runtime entrypoint via `runtime.js`. |
| Node LangChain-style adapter | ✅ Supported | Real runtime validation with `@langchain/core` | LangChain JS style tools | `wrapLangChainTool()` available. |
| Node OpenAI-style adapter | ✅ Supported | Real runtime validation with `@openai/agents` | OpenAI Agents style handlers | `wrapOpenAITool()` available. |
| Node ChatGPT Actions pattern | ✅ Example Available | Local end-to-end example server verified | Custom GPT / Actions prototypes | Uses an HTTP service behind GPT Actions. |
| Python binding | ✅ Supported | Python tests and demos | Python hosts and wrappers | Build-from-source flow. |
| Python LangChain adapter | 🟡 Beta | Wrapper + adapter tests, plus a real-package validation script | LangChain Python experiments | `wrap_langchain_tool()` available. A `tests/real_runtime_validation.py` script exercises the wrapper against real `langchain_core` `BaseTool`s, but CI does not yet run a framework version matrix automatically. |
| Python OpenAI-style adapter | 🟡 Beta | Wrapper + adapter tests | OpenAI-style handler integration in Python apps | `wrap_openai_tool()` available. Adapter test suite covers the handoff / deny / ask / error paths end-to-end; no CI version matrix yet. |
| AutoGen adapter | ⚪ Not shipped | No official adapter | No official adapter today | Still part of roadmap, not current official integration surface. |
| Claude Code plugin | 🟡 Preview | Hook adapter + plugin install validated | Claude Code users wanting an outbound gate | Gates built-in tools only — `Bash`, `Write`, `Edit`, `WebFetch`. **MCP tools (`mcp__*`) are not gated** ([#33106](https://github.com/anthropics/claude-code/issues/33106)); use the SDK for those. See [Claude Code plugin guide](../guides/operations/claude-code-plugin.md). |

---

## 2. Recommended Starting Point

For new users, the recommended order is:

1. Node quickstart
2. Node shell-tool protection
3. Node LangChain/OpenAI adapter path
4. Rust SDK or Python path as needed

Why:

- Node currently has the clearest high-level adapter story
- Node now has real runtime validation against actual framework packages
- Node includes the fastest "allowed vs blocked" onboarding loop
- shell-first execution control is the strongest current proof point in the repository

Start here:

- [Node quickstart](../../crates/agent-guard-node/examples/quickstart/README.md)
- [Secure shell tools guide](../guides/getting-started/secure-shell-tools.md)
- [Check vs enforce guide](../guides/getting-started/check-vs-enforce.md)

---

## 3. Node Support

### Core Package

Package:

- `crates/agent-guard-node`

Current state:

- raw binding available
- stable runtime entrypoint available
- high-level adapter layer available
- quickstart available
- ChatGPT Actions example available

Primary exports:

- `Guard`
- `createGuardedExecutor()`
- `wrapLangChainTool()`
- `wrapOpenAITool()`
- `AgentGuardDeniedError`
- `AgentGuardAskRequiredError`
- `AgentGuardExecutionError`

### Real Validation

The Node package is validated with:

- adapter unit tests
- native smoke tests
- real framework runtime tests

Current concrete validation inputs:

- `@langchain/core` `^0.3.75`
- `@openai/agents` `^0.8.3`
- `zod` `^4.3.6`

This means the Node package is no longer only a raw binding story. It is currently the strongest adoption surface in the repository.

### Recommended Use Cases

- shell tool protection
- OpenAI-style tool handlers
- LangChain-style JS tool objects
- internal HTTP tool gateways
- Custom GPT / Actions backends

---

## 4. Python Support

Package:

- `crates/agent-guard-python`

Current state:

- Python binding available
- LangChain and OpenAI-style wrappers available
- tests and examples available
- best described as beta rather than parity-complete

Primary documented paths:

- `wrap_langchain_tool()`
- `wrap_openai_tool()`

Best current fit:

- teams already in Python
- LangChain-oriented experimentation
- environments where build-from-source via Rust is acceptable

Important caveat:

The Python adapter layer is now official, but still below the current Node surface in maturity. A real-package validation script (`tests/real_runtime_validation.py`) exercises `wrap_langchain_tool` against actual `langchain_core` types, and the adapter unit suite covers handoff / deny / ask / error paths end-to-end; the remaining gap is an automated CI matrix that pins specific framework package versions per release.

Boundary note:

- Python and Node wrapper layers can guard many tool types at the policy level
- the strongest current `enforce` path across languages is still shell / Bash execution
- treat non-shell adapters primarily as `check` + policy gate surfaces unless your host adds a stronger execution boundary

---

## 5. Rust SDK Support

Crate:

- `agent-guard-sdk`

Current state:

- full policy and execution path available
- examples and integration tests available
- strongest direct control over execution pipeline

Best fit:

- custom host applications
- security-sensitive internal platforms
- teams that want the most explicit runtime control

If your team is building a bespoke runtime instead of adapting a framework, Rust is the most direct foundation.

---

## 6. ChatGPT / GPT Actions Support

Current state:

- no “inject directly into ChatGPT itself” path
- practical integration pattern documented
- example backend server included

Recommended architecture:

`Custom GPT` -> `Action` -> `your HTTP service` -> `agent-guard` -> `tool`

Best fit:

- demos
- internal proofs of concept
- teams validating ChatGPT-based workflows before building a full app

Reference:

- [ChatGPT Actions integration guide](../guides/getting-started/chatgpt-actions.md)

---

## 7. Maturity Legend

- ✅ Supported: official and recommended for active use
- 🟡 Beta: works and is documented, but should still be described with caution
- ⚪ Not shipped: roadmap item, not an official current surface

---

## 8. Current Messaging Guidance

When describing support publicly, use wording like:

- “Node adapters for LangChain-style tools and OpenAI-style handlers are available and validated against real framework packages.”
- “Python LangChain and OpenAI-style wrappers are available as beta paths.”
- “AutoGen remains a roadmap item.”
- “The Claude Code plugin gates the built-in tools where PreToolUse deny is enforced (`Bash`, `Write`, `Edit`, `WebFetch`); MCP tools are not gated by the hook (anthropics/claude-code#33106) and should be routed through the SDK.”
- “agent-guard is a primary control for OWASP Agentic ASI02 (Tool Misuse) and ASI05 (Unexpected Code Execution), and a containment/accountability backstop for ASI01/03/08/09/10.” (see §10)

Avoid wording like:

- “All major frameworks fully supported”
- “Cross-framework parity complete”
- “The Claude Code plugin gates every tool call” (it does not cover MCP tools)
- “Covers the OWASP Agentic Top 10” — it does not; ASI04 / ASI06 / ASI07 are out of scope (see §10)

Those overstate the current maturity level.

---

## 9. Recommended Next Expansion

The next useful improvements to this matrix would be:

1. explicit Node version support range
2. explicit Python version support range
3. framework-version test matrix in CI
4. AutoGen status updates when an official adapter lands

---

## 10. Threat Coverage — OWASP Agentic Top 10

> Scope note: this section is about **threat coverage**, not framework/binding
> readiness (the rest of this document). It maps `agent-guard` onto the OWASP
> Top 10 for Agentic Applications (ASI01–ASI10, OWASP GenAI Security Project,
> 2025-12). `agent-guard` is an *execution-control* layer, so it is strong on
> side-effect risks, a backstop on autonomy/blast-radius risks, and silent on
> the model-internal / memory / multi-agent risks. The ⬜ rows are deliberate.

Legend: ✅ primary control · 🟡 containment / blast-radius / accountability · ⬜ out of scope.

| ID | OWASP threat | Coverage | How / why |
| :--- | :--- | :---: | :--- |
| ASI01 | Agent Goal Hijack | 🟡 | No injection detection (that's an LLM-I/O guardrail). A hijacked agent still has to clear the action + content gate, bounding what it can do. |
| ASI02 | Tool Misuse | ✅ | The wedge: bash intent / destructive detection, workspace confinement, SSRF deny-list, outbound content scan. |
| ASI03 | Identity & Privilege Abuse | 🟡 | Least-agency scoping via `TrustLevel` (Untrusted default, escalation-proof) + `PolicyMode` + per-agent trust. Not an IAM / secret broker. |
| ASI04 | Agentic Supply Chain | ⬜ | Policy signing makes the *rules* tamper-evident, but we do not scan MCP servers / plugins / tools for poisoning. |
| ASI05 | Unexpected Code Execution | ✅ | Flagship: validator filtering + OS sandbox (seccomp / Seatbelt / Job Object / AppContainer) behind the decision boundary. Default build has no OS isolation — the decision layer is the only boundary unless a sandbox feature is compiled in. |
| ASI06 | Memory & Context Poisoning | ⬜ | We do not touch agent memory / vector stores / RAG. |
| ASI07 | Insecure Inter-Agent Communication | ⬜ | Single-agent execution control; multi-agent control plane is out of scope. |
| ASI08 | Cascading Failures | 🟡 | Deny Fuse circuit-breaker (lock after N denials in a window) + rate limiting bound a single runaway agent. |
| ASI09 | Human-Agent Trust Exploitation | 🟡 | Approval workflow + signed approval provenance insert and *record* a real human decision point before risky actions. |
| ASI10 | Rogue Agents | 🟡 | Deny Fuse lock-out + tamper-evident audit + Ed25519 execution proof make rogue actions detectable and attributable. |

**Defensible one-liner:** `agent-guard` is a *primary* control for **ASI02** and
**ASI05**, and a blast-radius / accountability backstop for **ASI01, ASI03,
ASI08, ASI09, ASI10** — with cryptographic execution proof as the through-line.
It is explicitly **not** a memory-poisoning (ASI06), MCP-supply-chain (ASI04),
or multi-agent-comms (ASI07) control.

Ids and titles verified against the OWASP official announcement
([genai.owasp.org](https://genai.owasp.org/), 2025-12-09); the prefix is **ASI**
(Agentic Security Initiative). The coverage judgements (✅/🟡/⬜) are this
project's own assessment. Working notes:
`docs/strategy/owasp-agentic-top10-mapping-2026-06.md` (local, not committed).
