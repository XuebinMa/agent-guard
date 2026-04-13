# Linux Seccomp Sandbox — agent-guard

> **Status:** v0.2.0 Linux Seccomp is still a prototype wrapper. Native Seccomp-BPF enforcement is planned for v0.3.0.

## Overview

The `SeccompSandbox` in `crates/agent-guard-sandbox/src/linux.rs` currently provides two modes:

- `SeccompSandbox::new()`: prototype wrapper around `sh -c` with timeout handling.
- `SeccompSandbox::strict()`: fail-closed mode that returns `FilterSetup` until native Seccomp-BPF enforcement is implemented.

This means the current Linux fallback does **not** yet install kernel syscall filters, block global writes, or block outbound network access by itself.

## Requirements

If you enable the optional `seccomp` feature today, Cargo will still pull in `libseccomp`, but the runtime path remains prototype-only in v0.2.0.

- Linux kernel 3.5+
- `libseccomp` development headers if building with the `seccomp` feature:
  - Ubuntu/Debian: `sudo apt-get install libseccomp-dev`
  - Fedora/RHEL: `sudo dnf install libseccomp-devel`
  - Alpine: `apk add libseccomp-dev`

## Feature Flag

```toml
[dependencies]
agent-guard-sandbox = { version = "0.2.0-rc1", features = ["seccomp"] }
```

## Current Behavior

| Constructor | Current behavior in v0.2.0 |
|---|---|
| `SeccompSandbox::new()` | Executes via `sh -c` in the requested working directory and enforces `timeout_ms` only. |
| `SeccompSandbox::strict()` | Fails closed with `SandboxError::FilterSetup(...)` instead of silently using the prototype wrapper. |

## Error Semantics

- `FilterSetup`: Returned by `strict()` until native Seccomp-BPF enforcement is available.
- `Timeout`: Execution exceeded `SandboxContext.timeout_ms`.
- `ExecutionFailed`: Process spawn or shell execution failed.

## Production Recommendation

Do not rely on the current Linux Seccomp fallback for kernel-level isolation. For Linux hosts today:

- Prefer `LandlockSandbox` when the host supports it.
- Use `SeccompSandbox::strict()` only when you want fail-closed behavior rather than a prototype wrapper.
- Treat `SeccompSandbox::new()` as a compatibility path, not as a hardened sandbox.

```rust
use agent_guard_sandbox::linux::SeccompSandbox;

let sandbox = SeccompSandbox::strict(); // Fails closed until native seccomp lands
```
