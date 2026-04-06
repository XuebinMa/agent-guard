# Linux Seccomp Sandbox — agent-guard

> **Note:** Requires `libseccomp` C library and `seccomp` feature flag.

## Overview

The `SeccompSandbox` (implemented in `crates/agent-guard-sandbox/src/linux.rs`) provides OS-level process isolation on Linux using `seccomp-bpf`. It intercepts system calls before they are executed and blocks any that are not explicitly allowed for the given `PolicyMode`.

## Requirements

To build with seccomp support:

- Linux kernel 3.5+
- `libseccomp` development headers installed:
  - Ubuntu/Debian: `sudo apt-get install libseccomp-dev`
  - Fedora/RHEL: `sudo dnf install libseccomp-devel`
  - Alpine: `apk add libseccomp-dev`

## Feature Flag

Enable the `seccomp` feature in `Cargo.toml`:

```toml
[dependencies]
agent-guard-sandbox = { version = "0.1.0", features = ["seccomp"] }
```

## Security Modes

The sandbox selects a syscall allowlist based on the `PolicyMode` resolved by the `PolicyEngine`.

| Mode | Syscall Allowlist (BPF filter) |
|---|---|
| `ReadOnly` | `read`, `openat` (O_RDONLY), `stat`, `mmap`, `close`, `exit_group`, etc. **Write is only allowed to stdout/stderr (fd ≤ 2)**. |
| `WorkspaceWrite` | `ReadOnly` + `write`, `openat` (O_WRONLY/O_RDWR), `creat`, `unlink`, `rename`, `mkdir`, `rmdir`, etc. |
| `FullAccess` | **No filter applied.** (Danger: full OS access) |

## Error Semantics

- `KilledByFilter`: The process attempted a blocked syscall and was killed by the kernel with `SIGSYS`.
- `FilterSetup`: The sandbox failed to initialize (e.g., `libseccomp` not available).
- `Timeout`: Execution exceeded `SandboxContext.timeout_ms`.

## Production Recommendation

Always use `SeccompSandbox::strict()` for production. If the filter fails to load, it will return an `Err` rather than falling back to `NoopSandbox`.

```rust
use agent_guard_sandbox::SeccompSandbox;

let sandbox = SeccompSandbox::strict(); // Fails-safe on error
```
