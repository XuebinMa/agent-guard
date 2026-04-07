# Global Threat Model — agent-guard

> Status: **Phase 4 v1 Complete**  
> This document serves as the primary security audit entry point for `agent-guard`. It outlines the assets, attack surfaces, and defensive posture of the SDK across all supported platforms.

---

## 1. 🏗️ Asset Inventory
What are we protecting?

| Asset | Importance | Security Requirement |
| :--- | :--- | :--- |
| **Policy Files (`policy.yaml`)** | **CRITICAL** | Integrity: Unauthorized modification leads to complete bypass. |
| **Audit Logs (JSONL)** | **HIGH** | Non-repudiability: Logs must be protected from tampering by the agent. |
| **Host System** | **CRITICAL** | Isolation: Prevent local privilege escalation (LPE) from sandboxed tools. |
| **Sensitive Data (Files/Env)** | **HIGH** | Confidentiality: Prevent unauthorized reading/exfiltration via tool calls. |
| **Network Resources** | **MEDIUM** | Availability/Confidentiality: Prevent SSRF or internal network scanning. |

---

## 2. 🏹 Attack Surface Inventory
Where can an attacker (malicious agent) strike?

### A. Tool Call Payloads (Primary)
The LLM generates JSON payloads for tools like `bash`. This is the most common entry point for **Prompt Injection** and **Command Injection**.
- **Vector**: Maliciously crafted shell commands, absolute paths, or nested script execution.
- **Mitigation**: Semantic validation via `PolicyEngine` + OS-level Sandbox.

### B. Local Filesystem
Tools often require read/write access to a workspace.
- **Vector**: Symlink attacks, path traversal (`../../`), or access to `/etc/passwd`.
- **Mitigation**: Path prefix validation + Workspace-locked sandboxes (Seccomp/Seatbelt).

### C. Network Execution
Agents may attempt to communicate with external C2 servers or internal metadata services (e.g., `169.254.169.254`).
- **Vector**: `curl`, `wget`, or raw socket calls from within a bash tool.
- **Mitigation**: Seccomp network blocking (Linux) or Seatbelt network deny rules (macOS).

---

## 3. 🛡️ STRIDE Threat Analysis

| Threat Category | Description | agent-guard Mitigation |
| :--- | :--- | :--- |
| **S**poofing | Actor impersonation in `Context`. | Trusted orchestrator must provide valid `actor_id`. |
| **T**ampering | Modifying policy or audit logs. | **Out of scope**: Requires OS-level file permissions. |
| **R**epudiation | Denying a destructive tool call was made. | Non-repudiable JSONL Audit Logs with request IDs. |
| **I**nformation Disclosure | Exfiltrating host secrets via tools. | Read-only/No-access policy modes + Sandboxing. |
| **D**enial of Service | Agent entering a loop to exhaust CPU/RAM. | **Phase 4**: Anomaly detection + Job Object limits. |
| **E**levation of Privilege | Escaping the sandbox to gain host root. | **Seccomp-BPF** (Linux) prevents most syscall-based escapes. |

---

## 4. 📊 Platform Capability Matrix (Sandbox Audit)

| Feature | Linux (Seccomp) | macOS (Seatbelt) | Windows (Job Object) |
| :--- | :---: | :---: | :---: |
| **Enforcement Level** | Kernel (BPF) | User-space Proxy | OS Job Management |
| **Syscall Filtering** | ✅ **Full (Allowlist)** | ❌ No | ❌ No |
| **Filesystem Isolation** | ✅ **Strict (Chroot-like)** | 🟡 **Experimental (Seatbelt)** | ❌ **Planned** |
| **Network Blocking** | ✅ **Native** | 🟡 **Experimental** | ❌ **No** |
| **Process Tree Cleanup** | ❌ (PID namespace planned) | ✅ **Yes** | ✅ **Yes (Kill on Close)** |
| **Resource Limits** | ✅ **Native** | ❌ **No** | ✅ **Verifiable Prototype** |

---

## 5. ☣️ Known Bypasses & Mitigations

### 1. Windows Filesystem Access (Phase 4)
- **Bypass**: Currently, the Windows `JobObject` does not restrict filesystem access. A malicious agent can still read any file the host user can access.
- **Mitigation**: Run the orchestrator as a dedicated **Low-Privilege User (LPU)** and use Windows ACLs.

### 2. Side-channel Information Leakage
- **Bypass**: Timing attacks or cache analysis from within a sandbox.
- **Mitigation**: Inherent limitation of software sandboxing. Avoid running highly sensitive multi-tenant workloads on the same physical core.

### 3. macOS Global Read
- **Bypass**: Current `macos-seatbelt` profile focuses on denying *writes* outside the workspace but may allow *reads* in some global directories.
- **Mitigation**: Explicitly add `(deny file-read*)` rules for sensitive paths in future profile updates.

---

## 6. 🛠️ Security Hardening Checklist

1. [ ] **Low-Privilege User**: Never run `agent-guard` as `root` or `Administrator`.
2. [ ] **Fail-Closed Config**: Ensure `Guard::execute()` is called and its error handled (never ignore a sandbox failure).
3. [ ] **Policy Immutability**: Set the `policy.yaml` file to read-only for the service user.
4. [ ] **Audit Offloading**: Ship JSONL logs to a remote, write-only logging server (e.g., ELK, CloudWatch).
5. [ ] **Anomaly Thresholds**: Tuned the `anomaly` detection limits to match your agent's expected tool usage patterns.
