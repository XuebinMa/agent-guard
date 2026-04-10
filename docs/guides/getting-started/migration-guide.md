# 🚀 Migration Guide

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Operational (v0.2.0) |
| **Audience** | Developers, DevOps |
| **Version** | 1.1 |
| **Last Reviewed** | 2026-04-08 |
| **Related Docs** | [User Manual](user-manual.md), [Capability Parity](../../capability-parity.md) |

---

This guide helps you transition from basic `NoopSandbox` execution to the hardened, OS-level sandboxes provided by `agent-guard`.

---

## 1. 🛡️ Determine Host Capabilities

Before switching sandboxes, verify what your host operating system supports using the **Capability Doctor**.

```bash
cargo run --example doctor
```

---

## 2. 🏗️ The Three-Stage Adoption Path

### Phase 1: No-op (Development Only)
- **Benefit**: Zero setup, full speed.
- **Risk**: **NO OS-level protection.** If a tool is compromised, the host is vulnerable.

### Phase 2: Restricted Token / Seatbelt (Prototype/Internal)
- **Benefit**: Prevents most accidental filesystem writes outside the workspace.
- **Risk**: Network and advanced syscalls are still accessible on some platforms.

### Phase 3: Linux Host Sandboxing (Current Prototype / Future Hardening)
- **Benefit**: Uses the strongest Linux backend available on the host today, with Landlock write isolation when supported.
- **Risk**: Full Seccomp-BPF syscall filtering is not yet shipped in v0.2.0.

---

## ⚠️ Security Boundaries (Transition Gaps)

| Transition | What you gain | What remains a gap |
| :--- | :--- | :--- |
| **No-op -> Low-IL** | Workspace write isolation on Windows. | Network access is still allowed by default. |
| **No-op -> Seatbelt**| Mandatory write-protection on macOS. | Global read access is still possible. |
| **No-op -> Linux Sandbox** | Landlock-backed write isolation when the host supports it. | No Linux Seccomp-BPF filtering yet; fallback hosts may still use the prototype wrapper. |

---

## 3. ⚠️ Compatibility Notes: Low-IL (Windows)

1. **Writing to `%TEMP%`**: Low-IL processes cannot write to the user's standard temp directory.
2. **Accessing Registry**: Most registry write operations will be denied.
3. **Shell Redirection**: Ensure paths with spaces are correctly quoted for `cmd /C`.

---

## 4. 🛠️ Best Practices for Transition

1. **Start with `Read-Only`**: Even without a sandbox, `agent-guard`'s DSL will block unauthorized `write` tool calls.
2. **Audit First**: Run in `Phase 1` for a few days, review your `audit.jsonl`, and see which paths your agents actually need.
3. **Fail-Closed**: Always check the `ExecuteResult` for `SandboxError`.
