# 📦 Release Notes v0.2.0

## 🚀 Overview
Version `v0.2.0` marks the transition of `agent-guard` from a core proof-of-concept to a **Enterprise-grade security layer**. This release introduces cross-platform enforcement, verifiable execution receipts, and deep observability integrations.

## ✨ Key New Features

### 🛡️ Strengthened Sandboxing
- **Windows Low-IL Enforcement**: Manual Win32 process spawning via `CreateProcessAsUserW` to enforce Low Integrity Level isolation (File system write protection).
- **Windows AppContainer (Opt-in)**: A new experimental prototype providing fine-grained, object-based isolation and restricted network access.
- **macOS Seatbelt (Active)**: Full migration from placeholder to real `sandbox-exec` enforcement with path canonicalization.

### 📜 Verifiable Execution (Provenance)
- **Signed Receipts**: Every tool execution can now generate an Ed25519-signed receipt containing the policy version, command hash, and sandbox details.
- **Tamper Evidence**: Host applications can cryptographically verify that an execution was performed under the claimed security context.

### 🚨 Enterprise Observability & SIEM
- **Unified Audit Events**: Standardized event model for tool calls, execution lifecycle, and security anomalies.
- **Webhook SIEM Exporter**: Push security events in real-time to external alerting and logging systems (e.g., Slack, PagerDuty, Grafana Loki).
- **Per-Agent Metrics**: All Prometheus metrics now include the `agent_id` label for granular monitoring.

### 🏥 Adoption Suite
- **Capability Doctor**: A built-in diagnostic tool (`cargo run --example doctor`) to inspect and verify host-level security features.
- **Migration Guide**: Clear documentation for moving from `No-op` to `Hardened` production environments.

## 🛠️ Internal Improvements
- **Unified Capability Model (UCM)**: Abstracted security capabilities away from OS-specific APIs.
- **Atomic Policy Reloading**: Snapshot isolation using `ArcSwap` for zero-downtime policy updates.
- **Fail-Closed Architecture**: Ensured that any failure in sandbox setup or pipe redirection results in a hard execution block.

## ⚠️ Known Gaps & Non-Goals
- **Windows Network (Low-IL)**: Standard Low-IL enforcement does not block network access; use the experimental AppContainer backend for network isolation.
- **Remote Attestation**: TPM-backed attestation is planned for v0.3.0. Currently, receipts are signed by the trusted SDK host.
- **Linux FS Virtualization**: Deep filesystem virtualization (namespaces) is targeted for the next major release.

## 🏁 Release Validation
This release has passed the **v0.2.0 Release Gate**:
- ✅ End-to-End full chain validation (Policy -> Metrics).
- ✅ Negative security boundary verification on all major platforms.
- ✅ Fail-closed robustness testing.
- ✅ Provenance receipt integrity checks.
- ✅ 3 Standardized demos implemented and verified.

---
**Full Documentation**: [Main Hub](README.md)
**Parity Matrix**: [Capability Parity Matrix](capability-parity.md)
