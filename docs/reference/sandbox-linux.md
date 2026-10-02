# Linux Sandboxes — agent-guard

> **Status:** Linux Seccomp supports native Seccomp-BPF filtering when built with the `seccomp` feature. Feature-built Landlock provides path-aware, mode-specific write isolation on hosts with Landlock ABI v3 or newer.

## Overview

The `SeccompSandbox` in `crates/agent-guard-sandbox/src/linux.rs` is fail-closed:

- `SeccompSandbox::new()`: requires native Seccomp-BPF and returns `FilterSetup` if any required syscall cannot be resolved or the complete filter cannot be loaded.
- `SeccompSandbox::strict()`: compatibility alias with the same fail-closed behavior.

The separate `LandlockSandbox` in
`crates/agent-guard-sandbox/src/landlock.rs` is the path-aware filesystem
boundary. It requires Landlock ABI v3 (upstream Linux 6.2+) as a hard minimum:
ABI v3 added the `TRUNCATE` right needed to govern `truncate(2)`,
`ftruncate(2)`, and `open(2)` with `O_TRUNC`. An older or partially enforced
ruleset is reported unavailable or fails setup instead of being described as
workspace isolation.

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
agent-guard-sandbox = { version = "0.2.0", features = ["seccomp"] }
```

## Current Behavior

| Constructor | Current behavior |
|---|---|
| `SeccompSandbox::new()` | Uses native seccomp and fails closed with `SandboxError::FilterSetup(...)` if every required deny rule cannot be installed. |
| `SeccompSandbox::strict()` | Compatibility alias for the same fail-closed behavior. |

## Capability Reporting vs Runtime Enforcement

`Sandbox::capabilities()` reports static sandbox-level metadata, not the exact
effective permissions of a specific execution.

For Linux seccomp, that means:

- `filesystem_write_global = true` because `workspace_write` remains path-agnostic and `full_access` skips the filter entirely.
- `network_outbound_any = true` because `full_access` intentionally leaves networking available.
- `read_only` executions can still be stricter at runtime than the static capability report: the seccomp filter blocks common write and networking syscalls for that mode.

Use the mode semantics below and the seccomp integration tests as the source of
truth for per-execution behavior.

## Mode Semantics

| Policy Mode | Native seccomp behavior |
|---|---|
| `ReadOnly` | Blocks common write/mutation syscalls and outbound networking syscalls while still allowing ordinary command execution and pipes. |
| `WorkspaceWrite` | Allows write syscalls, but still blocks networking and other dangerous kernel interfaces. Path-level workspace enforcement still comes from validators / policy. |
| `FullAccess` | No seccomp filter is loaded. |

### Landlock mode semantics

| Policy Mode | Landlock filesystem behavior |
|---|---|
| `Blocked` / `ReadOnly` | Global reads and executable loading remain available; no filesystem write rights are granted, including inside the workspace. |
| `WorkspaceWrite` | Global reads remain available; the complete ABI-v3 write set is granted only beneath the canonical workspace. |
| `FullAccess` | The complete ABI-v3 access set is granted globally. |

Landlock does not restrict networking in this backend. Static capability
metadata therefore reflects that `FullAccess` can write globally; the table
above is the source of truth for the stricter per-execution modes.

The Linux-only regression suite exercises write-open, `truncate`, inherited-FD
`ftruncate`, and read-only `O_TRUNC` behavior:

```bash
cargo test -p agent-guard-sandbox --features landlock --test landlock_integration -- --nocapture
```

## Error Semantics

- `FilterSetup`: Returned when native seccomp is unavailable, a required syscall cannot be resolved, or the complete filter cannot be installed.
- `KilledByFilter`: Returned if the kernel terminates the process with `SIGSYS`.
- `Timeout`: Execution exceeded `SandboxContext.timeout_ms`.
- `ExecutionFailed`: Process spawn or shell execution failed.

## Production Recommendation

For Linux hosts today:

- Prefer `LandlockSandbox` when the host supports it.
- Both constructors are fail-closed; use `strict()` when its name makes that requirement clearer at a call site.
- Treat seccomp as syscall-level defense in depth, not as a replacement for path-aware policy validation.

```rust
use agent_guard_sandbox::linux::SeccompSandbox;

let sandbox = SeccompSandbox::strict(); // Requires native seccomp filter installation
```
