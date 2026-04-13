# Linux Seccomp Sandbox — agent-guard

> **Status:** Linux Seccomp now supports native Seccomp-BPF filtering when built with the `seccomp` feature. Path-aware workspace isolation still requires higher-level validators or Landlock.

## Overview

The `SeccompSandbox` in `crates/agent-guard-sandbox/src/linux.rs` provides two operating styles:

- `SeccompSandbox::new()`: prefers native Seccomp-BPF when available, but can fall back to the compatibility `sh -c` wrapper if setup fails.
- `SeccompSandbox::strict()`: requires native Seccomp-BPF and returns `FilterSetup` instead of falling back.

With the `seccomp` feature enabled, read-only executions now install a syscall filter in the child process before `exec`, blocking network-oriented syscalls and common write/metadata mutation syscalls.

## Requirements

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
| `SeccompSandbox::new()` | Uses native seccomp on Linux when filter setup succeeds; otherwise falls back to the compatibility shell wrapper. |
| `SeccompSandbox::strict()` | Uses native seccomp and fails closed with `SandboxError::FilterSetup(...)` if the filter cannot be installed. |

## Mode Semantics

| Policy Mode | Native seccomp behavior |
|---|---|
| `ReadOnly` | Blocks common write/mutation syscalls and outbound networking syscalls while still allowing ordinary command execution and pipes. |
| `WorkspaceWrite` | Allows write syscalls, but still blocks networking and other dangerous kernel interfaces. Path-level workspace enforcement still comes from validators / policy. |
| `FullAccess` | No seccomp filter is loaded. |

## Error Semantics

- `FilterSetup`: Returned when native seccomp could not be initialized and `strict()` is used.
- `KilledByFilter`: Returned if the kernel terminates the process with `SIGSYS`.
- `Timeout`: Execution exceeded `SandboxContext.timeout_ms`.
- `ExecutionFailed`: Process spawn or shell execution failed.

## Production Recommendation

For Linux hosts today:

- Prefer `LandlockSandbox` when the host supports it.
- Use `SeccompSandbox::strict()` when you need fail-closed native seccomp instead of compatibility fallback.
- Treat seccomp as syscall-level defense in depth, not as a replacement for path-aware policy validation.

```rust
use agent_guard_sandbox::linux::SeccompSandbox;

let sandbox = SeccompSandbox::strict(); // Requires native seccomp filter installation
```
