# macOS Experimental Sandbox: Seatbelt (`sandbox-exec`)

The macOS sandbox implementation in `agent-guard` is an **experimental best-effort adapter** based on Apple's Seatbelt framework (via the `/usr/bin/sandbox-exec` CLI).

## ⚠️ Threat Model & Limitations

While the Linux implementation uses `seccomp-bpf` for fine-grained syscall filtering, the macOS Seatbelt implementation is currently a **filesystem-oriented prototype** with significant security limitations:

1.  **Deprecated Framework**: `sandbox-exec` is a legacy interface and has been formally deprecated by Apple. While it still works on modern macOS versions (Sequoia/Sonoma), it may be removed or further restricted in future updates.
2.  **Permissive Network Policy**: The current profile uses `(allow network*)`, meaning it provides **no network isolation**. Unlike the Linux sandbox, which can block network-related syscalls, the macOS sandbox allows all outbound and inbound connections.
3.  **Global Read Access**: To ensure developer tools (compilers, interpreters) function correctly, the profile currently uses `(allow file-read*)`. This means a sandboxed process can **read any file** on the system that the current user has permission to read (including SSH keys, browser cookies, etc.), even if the policy is set to `ReadOnly`.
4.  **No Syscall Filtering**: Seatbelt profiles in this implementation do not restrict specific syscalls. It relies entirely on path-based filesystem rules.
5.  **Signal/Process Exposure**: The sandbox allows `(allow process*)` and `(allow signal)`, meaning it does not prevent the sandboxed process from seeing or signaling other processes owned by the same user.

## Comparison: Linux vs. macOS

| Feature | Linux (Seccomp) | macOS (Seatbelt) |
|---|---|---|
| **Primary Goal** | Syscall-level Hardening | Path-based Filesystem Isolation |
| **Network** | Blocked by default | **Allowed** (current prototype) |
| **Read Access** | Restricted by policy | **Global** (user-level) |
| **Write Access** | Restricted to Workspace | Restricted to Workspace |
| **Security Level** | Production-ready | **Experimental / Prototype** |

## Implementation Details

The sandbox generates a Scheme-style profile at runtime:

```lisp
(version 1)
(deny default)
(allow process*)
(allow sysctl-read)
(allow signal)
(allow network*)
(allow file-read*)
;; Writes allowed to system temp/dev
(allow file-write* (subpath "/dev"))
(allow file-write* (subpath "/tmp"))
;; Workspace-specific write
(allow file-write* (subpath "/path/to/workspace"))
```

## Future Work

To reach parity with the Linux implementation, future versions of the macOS sandbox will need to:
- Move to the modern **App Sandbox** (App Sandbox entitlement) or **Endpoint Security framework**, though these typically require code signing and are less suitable for CLI tools.
- Refine the Seatbelt profile to restrict network and global read access once a stable set of "base" paths (e.g., `/usr/lib`, `/System/Library`) is identified.
