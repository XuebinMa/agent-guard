# agent-guard Project Architecture & Future Vision

> Status: **v0.2.0-rc1 Refined**  
> Date: April 2026

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

## 2. 🛡️ Current Security Posture (v0.2.0)

| Feature | Posture |
| :--- | :--- |
| **Logic** | Full YAML rule enforcement with regex payload validation. |
| **Windows** | Strengthened Prototype (Low-IL Enforced + AppContainer Opt-in). |
| **Linux** | Production Ready (Seccomp-BPF syscall filtering). |
| **macOS** | Active Prototype (Seatbelt FS isolation). |
| **Observability** | Enterprise-ready (Prometheus + SIEM Webhook). |

---

## 3. 🚀 Future Evolution Vision

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

### Phase 4: Cloud-Native Expansion
- **Native OTLP Support**: Direct gRPC/HTTP export to OpenTelemetry collectors.
- **K8s Sidecar Integration**: Provide a pre-configured sidecar container for seamless deployment in Kubernetes clusters.

---

## 🔍 Technical Debt & Risks
1. **Windows Dependency Weight**: The `windows` crate adds significant compile-time overhead; need to keep feature flags strictly modular.
2. **Platform Parity Gaps**: Linux and macOS currently have different FS-read boundaries; need to align these via Landlock/Seatbelt updates.
3. **Async SIEM**: Current Webhook export uses a basic thread-spawn; may need a robust internal queue for high-volume environments.
