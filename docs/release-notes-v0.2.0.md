# 📦 Release Notes v0.2.0-rc1

## 🚀 Overview
Version `v0.2.0-rc1` marks the transition of `agent-guard` from a core proof-of-concept to a production-shaped prerelease focused on shell-first enforcement, verifiable receipts, and transparent host capability reporting. This release strengthens the safest current path for high-risk shell tools while making trust and fallback behavior easier to verify.

## ✨ Key New Features

### 🛡️ Strengthened Sandboxing
- **Windows Low-IL Enforcement**: Manual Win32 process spawning via `CreateProcessAsUserW` to enforce Low Integrity Level isolation.
- **Windows AppContainer (Opt-in)**: A new experimental prototype providing SID-based isolation.
- **macOS Seatbelt (Host-Dependent)**: `sandbox-exec` enforcement is available when the runtime probe succeeds on the current host.
- **Linux Seccomp**: Native Seccomp-BPF filtering is now wired into restricted Linux executions when built with the `seccomp` feature. Path-aware workspace isolation still relies on validators and/or Landlock.

### 📜 Verifiable Execution (Provenance)
- **Signed Receipts**: Every tool execution can now generate an Ed25519-signed receipt containing the policy version, command hash, and sandbox details.
- **Tamper Evidence**: Host applications can cryptographically verify that an execution was performed under the claimed security context.

### 🚨 Enterprise Observability & SIEM
- **Unified Audit Events**: Standardized event model for tool calls, execution lifecycle, and security anomalies.
- **Webhook SIEM Exporter**: Push security events in real-time to external alerting and logging systems (e.g., Slack, PagerDuty, Grafana Loki).
- **Per-Agent Metrics**: All Prometheus metrics now include the `agent_id` label for granular monitoring.
- **Default Sandbox Diagnosis**: The SDK now exposes which sandbox backend `Guard::default_sandbox()` actually selects on the current host and why it may have fallen back to `NoopSandbox`.

### 🏥 Adoption Suite
- **Capability Doctor**: A built-in diagnostic tool exposed through `cargo run -p guard-verify -- doctor --format text|json|html` to inspect and verify host-level security features.
- **Transparent Fallback Reporting**: `doctor`, `dashboard`, and the transparency demo now surface runtime-unavailable sandboxes as explicit fail-closed fallback conditions instead of leaving operators to infer them.
- **Migration Guide**: Clear documentation for moving from `No-op` to `Hardened` production environments.

## 🛠️ Internal Improvements
- **Unified Capability Model (UCM)**: Abstracted security capabilities away from OS-specific APIs.
- **Atomic Policy Reloading**: Snapshot isolation using `ArcSwap` for zero-downtime policy updates.
- **Fail-Closed Architecture**: Ensured that any failure in sandbox setup or pipe redirection results in a hard execution block.

## ⚠️ Known Gaps & Non-Goals
- **Shell-First `enforce` Boundary**: The strongest `enforce` path in `v0.2.0-rc1` is shell / Bash execution. Non-shell tools primarily rely on `check` + policy gate unless the host application adds an extra runtime boundary.
- **Windows Network (Low-IL)**: Standard Low-IL enforcement does not block network access; use the experimental AppContainer backend for network isolation.
- **Host-Dependent Runtime Availability**: macOS Seatbelt and Windows Low-IL backends can be compiled in but still be unavailable at runtime. In those cases the SDK now reports the fallback explicitly and selects `NoopSandbox` rather than overstating protection.
- **Remote Attestation**: TPM-backed attestation is planned for a future trust-hardening release. Currently, receipts are signed by the trusted SDK host.
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
