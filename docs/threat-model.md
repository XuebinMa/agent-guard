# 🏹 Threat Model

| Field | Details |
| :--- | :--- |
| **Status** | 🟠 Active Review (v0.2.0) |
| **Audience** | Security Auditors, Compliance Officers |
| **Version** | 2.2 |
| **Last Reviewed** | 2026-04-08 |
| **Related Docs** | [Capability Parity](capability-parity.md), [Archive: Architecture & Future Directions](archive/architecture-and-vision.md) |

---

> This document serves as the primary security posture entry point for `agent-guard`. It outlines the assets, attack surfaces, and current defensive posture of the execution-control runtime across supported platforms.

---

## 1. 🏗️ Asset Inventory
The following assets are protected by the `agent-guard` execution control layer:

| Asset | Importance | Security Requirement |
| :--- | :--- | :--- |
| **Policy Files (`policy.yaml`)** | **CRITICAL** | **Integrity**: Unauthorized modification leads to complete bypass. Must be protected by OS-level permissions. |
| **Audit Logs (JSONL)** | **HIGH** | **Integrity / Availability**: Logs should be preserved for investigations, but local JSONL alone is not cryptographic non-repudiation. |
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
| **Filesystem Access** | Path traversal, Symlinks | Data exfiltration, Overwrite | Glob-based Allow/Deny paths + platform sandbox isolation (Landlock/Seatbelt/Windows token model). |
| **Network Stack** | Outbound HTTP/Socket | Data exfiltration, SSRF | Policy-level URL/path controls + platform sandboxing where available. |
| **Process Management** | Fork-bomb, child escape | DoS, Sandbox Escape | Job Objects (Windows) / cgroups (Linux Planned). |
| **Config Loader** | Malicious YAML config | Engine DoS, Logic Bypass | AOT Validation + Type-safe parsing + Schema enforcement. |

---

## 3. 🛡️ STRIDE Threat Analysis (v2.2 Refined)
Categorized analysis of threats and implemented defenses:

### **S**poofing (Identity)
- **Threat**: An unauthorized agent or actor impersonates a trusted one in the `Context`.
- **Mitigation**: The trusted host orchestrator is responsible for providing the immutable `actor` and `agent_id`.

### **T**ampering (Integrity)
- **Threat**: An agent modifies the security policy or deletes its own audit logs.
- **Mitigation**: **Out of scope for SDK** — requires OS-level file permissions (e.g., `chmod 400` on policy files).

### **R**epudiation (Non-repudiability)
- **Threat**: An attacker claims they did not execute a destructive command.
- **Mitigation**: Structured JSONL audit logs for forensic review, plus optional signed receipts for cryptographic provenance.

### **I**nformation Disclosure (Confidentiality)
- **Threat**: An agent reads host secrets (e.g., `.ssh/id_rsa`) via a `read_file` tool call.
- **Mitigation**: Mandatory `ReadOnly` modes + path-based deny-lists + OS-level Sandboxing.

### **D**enial of Service (Availability)
- **Threat**: An agent exhausts CPU/RAM or initiates a rapid-fire loop of tool calls.
- **Mitigation**: **Anomaly Detection** (frequency-based) + Windows Job Object resource limits (256MB default).

### **E**levation of Privilege (Isolation)
- **Threat**: An agent escapes the sandbox to gain root/Administrator privileges.
- **Mitigation**: **Low-IL Token + Job Object** (Windows), Seatbelt on macOS, and Landlock-backed write isolation on supported Linux hosts.

---

## 🛡️ Security Boundaries (Platform Mapping)

| Feature | Linux (Landlock if available, prototype fallback) | macOS (Seatbelt) | Windows (Job Object) |
| :--- | :--- | :--- | :--- |
| **Filesystem Write** | 🟡 Workspace write isolation on supporting hosts; fallback Linux wrapper is less strict. | ✅ Restricted (Workspace) | ✅ **Low-IL Enforced** |
| **Network Blocking** | ❌ Not enforced in the current Linux path. | 🟡 Experimental (Permissive) | ❌ **No** |
| **Resource Limits** | ❌ No native Linux sandbox resource caps in v0.2.0. | ❌ No | ✅ **Enforced (256MB)** |

---

## 🛠️ Security Hardening Checklist

1. [ ] **Low-Privilege User**: Never run `agent-guard` as `root` or `Administrator`.
2. [ ] **Fail-Closed Config**: Verify that `Guard::execute()` errors are handled as hard failures.
3. [ ] **Audit Offloading**: Send JSONL logs to a write-only remote destination.
4. [ ] **Metric Alerts**: Set alerts in Grafana for `agent_guard_anomaly_triggered_total > 0`.
