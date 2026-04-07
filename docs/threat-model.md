# Global Threat Model — agent-guard

> Status: **Phase 5 (Active)**  
> Version: **2.0**  
> This document serves as the primary security audit entry point for `agent-guard`. It outlines the assets, attack surfaces, and defensive posture of the SDK across all supported platforms.

---

## 1. 🏗️ Asset Inventory
What are we protecting?

| Asset | Importance | Security Requirement |
| :--- | :--- | :--- |
| **Policy Files (`policy.yaml`)** | **CRITICAL** | **Integrity**: Unauthorized modification leads to complete bypass. |
| **Audit Logs (JSONL)** | **HIGH** | **Non-repudiability**: Logs must be protected from tampering by the agent. |
| **Host System (Kernel/FS)** | **CRITICAL** | **Isolation**: Prevent local privilege escalation (LPE) and unauthorized writes. |
| **Secrets (Env/SSH Keys)** | **CRITICAL** | **Confidentiality**: Prevent unauthorized reading/exfiltration. |
| **Network (Local/External)** | **HIGH** | **SSRF Prevention**: Prevent internal network scanning and unauthorized C2 calls. |
| **Telemetry Data** | **MEDIUM** | **Availability**: Monitoring must persist during an attack. |

---

## 2. 🏹 Attack Surface Matrix

| Component | Entry Vector | Potential Impact | Mitigation Strategy |
| :--- | :--- | :--- | :--- |
| **Tool Payloads** | Malicious JSON/CLI args | Command Injection, RCE | `evalexpr` DSL + Regex Validation |
| **Filesystem** | Path traversal, Symlinks | Data exfiltration, Overwrite | Glob-based Allow/Deny + Sandbox isolation |
| **Network** | Outbound HTTP/Socket | Data exfiltration, SSRF | Seccomp (Linux) / Seatbelt (macOS Prototype) |
| **Process Tree** | Fork-bomb, child escape | DoS, Sandbox Escape | Job Objects (Windows) / cgroups (Planned) |
| **Policy Engine** | Malicious YAML config | Engine DoS, Logic Bypass | AOT Validation + Type-safe parsing |

---

## 3. 🛡️ STRIDE Threat Analysis

| Threat Category | Description | agent-guard v0.1.0 Mitigation |
| :--- | :--- | :--- |
| **S**poofing | Actor impersonation in `Context`. | Trusted orchestrator must provide valid `actor_id`. |
| **T**ampering | Modifying policy or audit logs. | **Out of scope**: Requires OS-level file permissions. |
| **R**epudiation | Denying a destructive tool call was made. | Non-repudiable JSONL Audit Logs + Prometheus Metrics. |
| **I**nformation Disclosure | Exfiltrating host secrets via tools. | Read-only modes + Workspace-locked Sandboxing. |
| **D**enial of Service | Agent exhausting CPU/RAM/Disk. | **Anomaly detection** + Windows Job Object limits. |
| **E**levation of Privilege | Escaping the sandbox to gain host root. | **Seccomp-BPF** (Linux) kernel-level enforcement. |

---

## 4. 📊 Platform Capability Matrix (Sandbox Audit)

| Feature | Linux (Seccomp) | macOS (Seatbelt) | Windows (Job Object) |
| :--- | :--- | :--- | :--- |
| **Isolation Backend** | Kernel-level BPF | User-space Proxy (`sandbox-exec`) | OS Job Object (`windows-sys`) |
| **Primary Goal** | Syscall Hardening | Filesystem Isolation | Resource & Lifecycle Mgmt |
| **Network Blocking** | ✅ Native (Strict) | 🟡 Experimental (Permissive) | ❌ **No** |
| **Filesystem Read** | ✅ Restricted | ❌ No (Global User Read) | ❌ No (Global User Read) |
| **Filesystem Write** | ✅ Restricted | ✅ Restricted (Workspace) | ❌ No (Global User Write) |
| **Resource Limits** | ✅ Native | ❌ No | ✅ **Verifiable Prototype** |
| **Fail-Closed** | ✅ Yes | ✅ Yes | ✅ Yes |

---

## 5. ☣️ Known Bypasses & Mitigations

### 1. Windows Global Filesystem Write
- **Bypass**: Currently, the Windows Job Object does not restrict filesystem access.
- **Mitigation (Phase 5)**: Run under a **Low-Integrity (Low-IL) Token**. In Phase 4, users must run as a dedicated restricted user account.
- **Reference**: See [docs/sandbox-windows.md](sandbox-windows.md).

### 2. macOS Global Read Access
- **Bypass**: The Seatbelt prototype focuses on write-prevention. It may allow reading system files accessible by the user.
- **Mitigation**: Future App Sandbox integration. Current users should avoid placing secrets in user-readable world directories.
- **Reference**: See [docs/sandbox-macos.md](sandbox-macos.md).

### 3. Time-of-Check to Time-of-Use (TOCTOU)
- **Bypass**: A symlink could be swapped between policy validation and sandbox execution.
- **Mitigation**: Sandboxes execute using the *already validated* path and provide kernel-level path resolution constraints where possible.

---

## 6. 🛠️ Security Hardening Checklist

1. [ ] **Low-Privilege User**: Never run `agent-guard` as `root` or `Administrator`.
2. [ ] **Fail-Closed Config**: Verify that `Guard::execute()` errors are handled as hard failures.
3. [ ] **Policy Immutability**: Use `chmod 400` on `policy.yaml` after deployment.
4. [ ] **Audit Offloading**: Send JSONL logs to a write-only remote destination.
5. [ ] **Metric Alerts**: Set alerts in Grafana for `agent_guard_anomaly_triggered_total > 0`.
