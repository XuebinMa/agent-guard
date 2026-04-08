# 🚀 Migration Guide: From No-op to Hardened Sandboxes

This guide helps you transition from basic `NoopSandbox` execution to the hardened, OS-level sandboxes provided by `agent-guard`.

---

## 1. 🛡️ Determine Host Capabilities

Before switching sandboxes, verify what your host operating system supports using the **Capability Doctor**.

```rust
use agent_guard_sdk::CapabilityDoctor;

let reports = CapabilityDoctor::report();
for report in reports {
    if report.is_available {
        println!("Available: {} ({})", report.name, report.sandbox_type);
    }
}
```

Or run the example:
`cargo run --example doctor`

---

## 2. 🏗️ The Three-Stage Adoption Path

### Phase 1: No-op (Development Only)
- **Target**: Local development and debugging.
- **Config**: `default_mode: read_only` (logic-level only).
- **Benefit**: Zero setup, full speed.
- **Risk**: **NO OS-level protection.** If a tool is compromised, the host is vulnerable.

### Phase 2: Restricted Token / Seatbelt (Prototype/Internal)
- **Target**: Internal testing on Windows or macOS.
- **Config**: Ensure your application has permissions to create Restricted Tokens (Windows) or call `sandbox-exec` (macOS).
- **Benefit**: Prevents most accidental filesystem writes outside the workspace.
- **Risk**: Network and advanced syscalls are still accessible.

### Phase 3: Seccomp-BPF (Production Ready - Linux Only)
- **Target**: Cloud deployments (Kubernetes, AWS Lambda, Docker).
- **Config**: `default_mode: read_only` + Linux kernel support.
- **Benefit**: **Maximum security.** Blocks unauthorized syscalls, network stack, and filesystem access at the kernel level.
- **Risk**: Higher complexity; certain CLI tools might break if they require specific syscalls (see "Compatibility Notes").

---

## 3. ⚠️ Compatibility Notes: Low-IL (Windows)

When running on Windows with **Low Integrity Level (Low-IL)** enforcement, some common operations will fail:

1. **Writing to `%TEMP%`**: Low-IL processes cannot write to the user's standard temp directory. Use a subdirectory within your designated `working_directory`.
2. **Accessing Registry**: Most registry write operations will be denied.
3. **Environment Variables**: Some user-level environment variables may be inaccessible or different.
4. **Shell Redirection**: The current `agent-guard` Windows implementation uses `cmd /C`. Ensure paths with spaces are correctly quoted.

---

## 4. 🛠️ Best Practices for Transition

1. **Start with `Read-Only`**: Even without a sandbox, `agent-guard`'s DSL will block unauthorized `write` tool calls.
2. **Use a Dedicated Workspace**: Always set a specific `working_directory`. Do NOT run agents in your user root or project root.
3. **Audit First**: Run in `Phase 1` for a few days, review your `audit.jsonl`, and see which paths your agents actually need.
4. **Fail-Closed**: Always check the `ExecuteResult`. If it contains a `SandboxError`, treat it as a security event and investigate.

---

## 5. 🚨 Common Error Codes

| Error | Cause | Fix |
| :--- | :--- | :--- |
| `NotAvailable` | OS doesn't support the sandbox. | Run `CapabilityDoctor` to see alternatives. |
| `FilterSetup` | Linux Seccomp library missing. | `sudo apt-get install libseccomp-dev` |
| `ExecutionFailed` | Win32 permission error. | Ensure parent process has `SeTcbPrivilege` or run as a standard user. |
| `KilledByFilter` | Agent tried an unauthorized syscall. | Check if the tool actually needs that syscall and update policy if safe. |
