# Global Threat Model — agent-guard

`agent-guard` is designed to provide security and oversight for AI agents executing tools. This document describes the security boundaries, assumed trust, and known limitations across supported platforms.

## 🛡️ Security Goals

1.  **Policy Enforcement**: Ensure tool calls (arguments, actors, contexts) match the declared policy before execution.
2.  **Audit Trail**: Provide a non-repudiable log of all tool call decisions and outcomes.
3.  **Process Isolation**: Execute potentially dangerous tools (e.g., `bash`) in a secure, restricted environment.
4.  **Resource Limiting**: Prevent agents from exhausting system resources (CPU, memory, file handles).

## 🛡️ Trust Boundaries

### Trusted (Must Be Secured)
- **Policy Storage**: The YAML policy files must be protected from unauthorized write access.
- **Audit Logs**: The audit log target must be secured to prevent tampering with or deletion of historical data.
- **Agent Orchestrator**: The code calling `agent-guard` is assumed to be trusted (as it passes the `Context`).

### Untrusted
- **AI Agent (LLM)**: The LLM's output (tool call payload) is considered untrusted and potentially malicious.
- **Sub-processes**: Any process spawned by a tool is considered untrusted and must be sandboxed.

## 🛡️ Platform Comparison (Sandbox)

| Security Feature | Linux (Seccomp) | macOS (Seatbelt) | Windows (Job Object) |
|---|---|---|---|
| **Syscall Filtering** | **Native (BPF)** | No | No |
| **Filesystem Write** | **Restricted** | **Restricted** (Best-effort) | No |
| **Filesystem Read** | **Restricted** | No (Global) | No (Global) |
| **Network Block** | **Native** | No (Allowed) | No (Allowed) |
| **Resource Limits** | Native | Native | **Native** |
| **Maturity** | Production-ready | Experimental | Experimental |

## 🛡️ Known Limitations & Vulnerabilities

### 1. Side-channel Attacks
Sandboxes do not fully prevent side-channel attacks (e.g., timing, CPU cache analysis). If an agent can measure time or observe CPU state, it may leak sensitive information.

### 2. Kernel Vulnerabilities
The sandbox relies on the host kernel for enforcement. A kernel-level exploit (e.g., local privilege escalation) could allow a sandboxed process to escape.

### 3. Exfiltration via Allowed Channels
If a policy allows network access or writes to a specific directory, the agent can use those channels to exfiltrate data. `agent-guard` only restricts *access* to channels, not the *content* sent over allowed channels.

### 4. macOS/Windows Prototype Status
As noted in [docs/sandbox-macos.md](sandbox-macos.md) and [docs/sandbox-windows.md](sandbox-windows.md), the current non-Linux implementations are prototypes. They do not yet provide full network or global read isolation.

## 🛡️ Recommended Security Posture

1.  **Least Privilege**: Run the agent and its orchestrator under a dedicated, low-privilege system user.
2.  **Defense-in-Depth**: Combine `agent-guard` with network-level firewalls (e.g., `iptables`, `Windows Firewall`) and filesystem-level permissions.
3.  **Strict Policy**: Start with a `ReadOnly` policy and only add specific `WorkspaceWrite` allowlists as needed.
4.  **Audit Review**: Regularly review audit logs for anomalous activity.
5.  **Telemetry**: Use the Phase 4 telemetry features to monitor for high-frequency or unusual tool call patterns.
