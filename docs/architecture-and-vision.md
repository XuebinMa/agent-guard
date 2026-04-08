# 🏗️ Architecture & Vision

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Finalized (v0.2.0) |
| **Audience** | Architects, Security Engineers |
| **Version** | 1.1 |
| **Last Reviewed** | 2026-04-08 |
| **Related Docs** | [Threat Model](threat-model.md), [Capability Parity](capability-parity.md) |

---

## 1. 🏗️ High-Level Architecture

`agent-guard` is structured as a multi-layered security wrapper designed to intercept, evaluate, and isolate LLM tool calls.

### A. Core Engine (`agent-guard-core`)
- **Policy Engine**: A YAML-driven rule evaluator using a restricted DSL (`evalexpr`).
- **Unified Capability Model (UCM)**: Abstract permissions (e.g., `filesystem_write_workspace`) that decouple policy intent from OS-specific implementations.
- **Unified Audit Model**: A standardized schema for all security events (tool calls, anomalies, sandbox failures).

### B. Integration Layer (`agent-guard-sdk`)
- **Guard Struct**: Manages state with **Atomic Reloading** (`ArcSwap`) and **Snapshot Isolation**.
- **Execution Pipeline**: `Check` -> `Anomaly Filter` -> `Audit` -> `Metrics` -> `Sandbox Execute`.
- **FFI Bindings**: Exposes core logic to Node.js and Python ecosystems.

### C. Isolation Layer (`agent-guard-sandbox`)
- **Linux**: `Seccomp-BPF` (Syscall filtering).
- **macOS**: `Seatbelt` (`sandbox-exec` via manual profile generation).
- **Windows**: `Low-IL` (Win32 Restricted Tokens) and `AppContainer` (Experimental SID-based isolation).
- **Capability Doctor**: Host-level diagnostic tool for security feature reporting.

### D. Verification & Trust (`agent-guard-sdk/provenance`)
- **Signed Receipts**: Ed25519 cryptographic proofs of execution context.
- **Fail-Closed Design**: Hard errors on any initialization or isolation failure.

---

## 🛡️ Security Boundaries (v0.2.0)

| Category | What this protects | What this does not protect |
| :--- | :--- | :--- |
| **Filesystem** | Prevents unauthorized writes to system directories and reads of sensitive files (platform dependent). | Global read access on macOS/Windows (Low-IL). |
| **Execution** | Ensures only approved commands with safe arguments reach the OS. | Logical errors in allowed scripts (e.g., an allowed script deleting its own data). |
| **Probing** | Automatically locks agents that repeatedly violate security policies. | Distributed attacks from multiple agents (Actor-based only). |
| **Trust** | Provides cryptographic proof that an execution happened under a specific policy. | Protection against host-level private key theft (TPM planned). |

---

## 🚀 Future Evolution Vision

### Phase 1: Isolation Fidelity (v0.3.0)
- **Linux Landlock**: Integrate Landlock for fine-grained, path-based filesystem isolation at the kernel level.
- **Windows AppContainer Maturity**: Promote AppContainer to the primary Windows backend to enable native network isolation.
- **User-Namespace Sandboxing**: Explore unprivileged containerization (e.g., `bubblewrap` style) for stronger Linux isolation without root.

### Phase 2: Hardware-Rooted Trust
- **TPM Remote Attestation**: Move execution receipt signing into the TPM (Trusted Platform Module) to prevent host-level forgery.
- **Policy Pinning**: Implement cryptographically immutable policy versions referenced by receipts.

### Phase 3: Semantic Guarding
- **LLM-Based Anomaly Detection**: Use small local models to detect semantic drift in tool usage (e.g., an agent behaving "out of character").
- **Dynamic Risk Scoring**: Adjust policy strictness in real-time based on the agent's recent audit history.

---

## 🔍 Technical Debt & Risks
1. **Windows Dependency Weight**: The `windows` crate adds significant compile-time overhead; need to keep feature flags strictly modular.
2. **Platform Parity Gaps**: Linux and macOS currently have different FS-read boundaries; need to align these via Landlock/Seatbelt updates.
3. **Async SIEM**: Current Webhook export uses a shared runtime but lacks persistent queuing for crash-resilience.
