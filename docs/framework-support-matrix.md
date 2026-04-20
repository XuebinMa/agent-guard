# Framework Support Matrix

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Active Support Snapshot |
| **Audience** | Developers, Integrators |
| **Version** | 1.0 |
| **Last Reviewed** | 2026-04-15 |
| **Related Docs** | [README](../README.md), [Node README](../crates/agent-guard-node/README.md), [Python README](../crates/agent-guard-python/README.md) |

---

This matrix answers the practical adoption questions for the current execution-control surface:

- which integration surfaces are available today?
- how mature are they?
- what has been validated in the repository?
- what should a new user try first?

This is not the same as the OS sandbox matrix in [capability-parity.md](capability-parity.md).  
That document describes platform enforcement boundaries.  
This document describes framework and binding readiness.

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
| Python LangChain adapter | 🟡 Beta | Repository wrappers and tests | LangChain Python experiments | Official wrapper surface is present, but not yet validated against a real framework version matrix in CI. |
| Python OpenAI-style adapter | 🟡 Beta | Repository wrappers and tests | OpenAI-style handler integration in Python apps | Official wrapper surface is available, but runtime validation is currently wrapper-level rather than package-level. |
| AutoGen adapter | ⚪ Not shipped | No official adapter | Future ecosystem target | Still part of roadmap, not current official integration surface. |

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

- [Node quickstart](../crates/agent-guard-node/examples/quickstart/README.md)
- [Secure shell tools guide](guides/getting-started/secure-shell-tools.md)
- [Check vs enforce guide](guides/getting-started/check-vs-enforce.md)

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

The Python adapter layer is now official, but still below the current Node surface in maturity. The main missing step is real framework-package validation in CI, not basic wrapper availability.

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

- [ChatGPT Actions integration guide](guides/getting-started/chatgpt-actions.md)

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

Avoid wording like:

- “All major frameworks fully supported”
- “Cross-framework parity complete”

Those overstate the current maturity level.

---

## 9. Recommended Next Expansion

The next useful improvements to this matrix would be:

1. explicit Node version support range
2. explicit Python version support range
3. framework-version test matrix in CI
4. AutoGen status updates when an official adapter lands
