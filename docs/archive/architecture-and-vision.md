# 🏗️ Architecture & Future Directions

| Field | Details |
| :--- | :--- |
| **Status** | 🟠 Maintainer Reference |
| **Audience** | Maintainers, Architects, Product Managers, Security Engineers |
| **Version** | 1.4 |
| **Last Reviewed** | 2026-04-20 |
| **Related Docs** | [User Manual](../guides/getting-started/user-manual.md), [Threat Model](../threat-model.md) |

---

This document is not the primary product entry point. It captures how the current execution-control architecture fits together and where the project may expand later.

The current product truth is narrower than a broad security-platform story:

- `agent-guard` sits between agent tool intent and real execution
- the clearest proof point today is shell-first execution control
- trust tooling, framework breadth, and future control-plane ideas are supporting or later-stage layers, not the phase-one hook

## 1. 🏗️ Current Architecture

`agent-guard` is best understood as an execution control layer for agent side effects. The current runtime focuses on making pre-execution decisions, enforcing the strongest available execution boundary, and producing auditable outcomes.

### A. Decision Layer (`agent-guard-core`)
- **Policy Engine**: YAML-driven rule evaluation with regex and DSL validation.
- **Decision Model**: Allow, deny, ask, and execution-control outcomes at the tool boundary.

### B. Integration Layer (`agent-guard-sdk`)
- **Adapter Surfaces**: Node and Python bindings, plus LangChain-style and OpenAI-style wrappers.
- **Execution Pipeline**: Check -> Filter -> Audit -> Sandbox.

### C. Execution Boundary Layer (`agent-guard-sandbox`)
- **Platform Backends**: Linux, macOS, and Windows sandbox paths with host-dependent behavior.
- **Shell-First Enforcement**: The strongest current `enforce` path remains shell / Bash execution.

### D. Audit And Verification Support
- **Receipts And Logs**: Auditable execution outcomes and optional signed provenance support.
- **Transparency Tooling**: Doctor-style host reporting to show what boundary is actually active.

---

## 🛡️ Security Boundaries (v0.2.0 Baseline)

| Category | What this protects | What this does not protect |
| :--- | :--- | :--- |
| **Filesystem** | Prevents unauthorized writes to system directories. | Global read access on macOS/Windows (v0.2 limit). |
| **Execution** | Ensures only approved commands reach the OS. | Logical errors in allowed scripts. |
| **Probing** | Automatically locks agents after repeated violations (Deny Fuse). | Distributed attacks across many unique actors. |
| **Trust** | Cryptographic proof of execution context. | Host-level key theft (TPM planned). |

---

## 🚀 Future Directions

The roadmap below is expansion context, not a statement of current product scope.

### Near Term
- deepen the shell-first execution-control story
- make Node and Python integration paths easier to adopt
- sharpen support and reference docs so developers can understand capability boundaries quickly

### Medium Term
- expand from shell-first control into a broader side-effect execution model
- improve resumable ask/deny/takeover flows
- go deeper on a few high-value side effects instead of claiming universal capability coverage

### Longer Term
- add stronger policy workflow and lifecycle tooling
- revisit more centralized control-plane patterns only after the execution-control wedge is clearly won
- treat enterprise-wide policy registry and audit intelligence as later overlays, not present-day product identity

---

## 🔍 Technical Debt & Risks
1. **Integration Surface**: Supporting multiple bindings and adapters increases maintenance surface and documentation complexity.
2. **Capability Breadth**: The project is still strongest on shell-first execution, so broader side-effect coverage must be sequenced carefully.
3. **Key Management**: Signed receipts and policy verification remain useful but should not displace the execution-control story.
4. **Fallback Semantics**: `NoopSandbox` fallback keeps policy controls but is not equivalent to native OS isolation, so the selected backend must remain operator-visible.
