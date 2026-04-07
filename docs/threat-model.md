# Global Threat Model — agent-guard

> Status: **Phase 5 (Active)**  
> Version: **2.0**  
> This document serves as the primary security audit entry point for `agent-guard`. It outlines the assets, attack surfaces, and defensive posture of the SDK across all supported platforms.

---

## 1. 🏗️ Asset Inventory
The following assets are protected by the `agent-guard` security layer:

| Asset | Importance | Security Requirement |
| :--- | :--- | :--- |
| **Policy Files (`policy.yaml`)** | **CRITICAL** | **Integrity**: Unauthorized modification leads to complete bypass. Must be protected by OS-level permissions. |
| **Audit Logs (JSONL)** | **HIGH** | **Non-repudiability**: Logs must be protected from tampering to maintain the chain of custody for security investigations. |
| **Host System (Kernel/FS)** | **CRITICAL** | **Isolation**: Prevent local privilege escalation (LPE) and unauthorized writes to critical system paths. |
| **Secrets (Env/SSH Keys)** | **CRITICAL** | **Confidentiality**: Prevent unauthorized reading or exfiltration of sensitive developer credentials. |
| **Network (Local/External)** | **HIGH** | **SSRF Prevention**: Prevent internal network scanning and unauthorized command-and-control (C2) communication. |
| **Telemetry Data** | **MEDIUM** | **Availability**: Real-time monitoring data must persist even if an agent process crashes or is compromised. |

---

## 2. 🏹 Attack Surface Matrix
Mapping potential entry points and their mitigation strategies:

| Surface Component | Entry Vector | Potential Impact | Mitigation Strategy |
| :--- | :--- | :--- | :--- |
| **Tool Payloads** | Malicious JSON/CLI args | Command Injection, RCE | `evalexpr` Restricted DSL + Regex Validation Patterns. |
| **Filesystem Access** | Path traversal, Symlinks | Data exfiltration, Overwrite | Glob-based Allow/Deny paths + Sandbox isolation (Seccomp/Seatbelt). |
| **Network Stack** | Outbound HTTP/Socket | Data exfiltration, SSRF | Seccomp (Linux) / Seatbelt (macOS Prototype). |
| **Process Management** | Fork-bomb, child escape | DoS, Sandbox Escape | Job Objects (Windows) / cgroups (Linux Planned). |
| **Config Loader** | Malicious YAML config | Engine DoS, Logic Bypass | AOT Validation + Type-safe parsing + Schema enforcement. |

---

## 3. 🛡️ STRIDE Threat Analysis
Categorized analysis of threats and implemented defenses:

### **S**poofing (Identity)
- **Threat**: An unauthorized agent or actor impersonates a trusted one in the `Context`.
- **Mitigation**: The trusted host orchestrator is responsible for providing the immutable `actor_id` and `agent_id`.

### **T**ampering (Integrity)
- **Threat**: An agent modifies the security policy or deletes its own audit logs.
- **Mitigation**: **Out of scope for SDK** — requires OS-level file permissions (e.g., `chmod 400` on policy files).

### **R**epudiation (Non-repudiability)
- **Threat**: An attacker claims they did not execute a destructive command.
- **Mitigation**: Non-repudiable JSONL Audit Logs + Real-time Prometheus Metrics (`agent_guard_decision_total`).

### **I**nformation Disclosure (Confidentiality)
- **Threat**: An agent reads host secrets (e.g., `.ssh/id_rsa`) via a `read_file` tool call.
- **Mitigation**: Mandatory `ReadOnly` modes + path-based deny-lists + OS-level Sandboxing.

### **D**enial of Service (Availability)
- **Threat**: An agent exhausts CPU/RAM or initiates a rapid-fire loop of tool calls.
- **Mitigation**: **Anomaly Detection** (frequency-based) + Windows Job Object resource limits.

### **E**levation of Privilege (Isolation)
- **Threat**: An agent escapes the sandbox to gain root/Administrator privileges.
- **Mitigation**: **Seccomp-BPF** (Linux) and **Low-IL Token + Job Object** (Windows).

---

## 4. 📊 Platform Capability Matrix (Sandbox Audit)

| Feature | Linux (Seccomp) | macOS (Seatbelt) | Windows (Job Object) |
| :--- | :--- | :--- | :--- |
| **Isolation Backend** | Kernel-level BPF | User-space Proxy (`sandbox-exec`) | OS Job Object + Low-IL Token |
| **Primary Goal** | Syscall Hardening | Filesystem Isolation | Resource & Filesystem Isolation |
| **Network Blocking** | ✅ Native (Strict) | 🟡 Experimental (Permissive) | ❌ **No** |
| **Filesystem Read** | ✅ Restricted | ❌ No (Global User Read) | ❌ No (Global User Read) |
| **Filesystem Write** | ✅ Restricted | ✅ Restricted (Workspace) | ✅ **Low-IL Enforced** |
| **Resource Limits** | ✅ Native | ❌ No | ✅ **Verifiable** |
| **Fail-Closed** | ✅ Yes | ✅ Yes | ✅ **Yes** |

---

## 5. ☣️ Known Bypasses & Mitigations

### 1. Windows Global Filesystem Access
<<<<<<< HEAD
- **Status**: **Strengthened Prototype (M5.1)**. 
- **Mitigation**: **Low-Integrity Level (Low-IL)** token enforcement is **ACTIVE** via `CreateProcessAsUserW`. This prevents writing to medium/high integrity folders even if the parent user process has access.
- **Reference**: See [docs/sandbox-windows.md](sandbox-windows.md).
=======
- **Status**: **ACTIVE (M5.1)**. 
- **Mitigation**: **Low-Integrity Level (Low-IL)** token enforcement is **ENFORCED** via Win32 `CreateProcessAsUserW`. This prevents writing to medium/high integrity folders (e.g., `C:\Windows`, `C:\Program Files`) even if the host user has Administrator privileges.
- **Reference**: See [crates/agent-guard-sandbox/src/windows.rs](../crates/agent-guard-sandbox/src/windows.rs).
>>>>>>> 02d1b74

### 2. macOS Global Read Access
- **Bypass**: The Seatbelt prototype focuses on write-prevention.
- **Mitigation**: Recommend running under a dedicated restricted system user.

### 3. Time-of-Check to Time-of-Use (TOCTOU)
- **Bypass**: Symlink swapping during tool validation.
- **Mitigation**: Sandboxes provide kernel-level path resolution constraints where possible.

---

## 6. 🛠️ Security Hardening Checklist

1. [ ] **Low-Privilege User**: Never run `agent-guard` as `root` or `Administrator`.
2. [ ] **Fail-Closed Config**: Verify that `Guard::execute()` errors are handled as hard failures.
3. [ ] **Audit Offloading**: Send JSONL logs to a write-only remote destination.
4. [ ] **Metric Alerts**: Set alerts in Grafana for `agent_guard_anomaly_triggered_total > 0`.
