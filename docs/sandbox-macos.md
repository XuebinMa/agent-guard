# macOS Experimental Sandbox: Seatbelt (`sandbox-exec`)

The macOS sandbox implementation in `agent-guard` is an **experimental best-effort adapter** based on Apple's Seatbelt framework (via the `/usr/bin/sandbox-exec` CLI). 

**Important**: This is not equivalent to the Linux seccomp sandbox and should not be treated as the same security boundary.

## ⚠️ Threat Model & Limitations

While the Linux implementation uses `seccomp-bpf` for fine-grained syscall filtering, the macOS Seatbelt implementation is currently a **filesystem-oriented prototype** with significant security limitations:

1.  **Deprecated Framework**: `sandbox-exec` is a legacy interface and has been formally deprecated by Apple. While it still works on modern macOS versions (Sequoia/Sonoma), it may be removed or further restricted in future updates.
2.  **Runtime Availability Risk**: Because this implementation depends on `/usr/bin/sandbox-exec`, availability is host-dependent. On hosts where Apple has disabled or removed that tool, `SeatbeltSandbox::is_available()` returns `false`, capabilities are reported as unavailable, and execution fails closed instead of silently degrading.
3.  **Global Read Access**: To ensure developer tools (compilers, interpreters) function correctly, the profile currently uses `(allow file-read*)`. This means a sandboxed process can **read any file** on the system that the current user has permission to read (including SSH keys, browser cookies, etc.), even if the policy is set to `ReadOnly`.
4.  **Coarse-Grained Filesystem Policy**: The current profile allows workspace writes and denies all network access, but it does so with broad Seatbelt path rules rather than syscall-level mediation. It should be treated as a best-effort containment layer, not a hardened isolation boundary.
5.  **No Syscall Filtering**: Seatbelt profiles in this implementation do not restrict specific syscalls. It relies entirely on path-based filesystem rules.

## Use Cases

### Suitable for:
- Local development and testing.
- Best-effort workspace write isolation.
- Demos and experimentation.

### NOT suitable for:
- Handling highly sensitive secrets (e.g., SSH keys, credentials).
- Hostile multi-tenant execution.
- Strong exfiltration resistance.

## Comparison: Linux vs. macOS

| Feature | Linux (Seccomp) | macOS (Seatbelt) |
|---|---|---|
| **Primary Goal** | Syscall-level Hardening | Path-based Filesystem Isolation |
| **Network** | Blocked by default | Blocked when Seatbelt runtime is available |
| **Read Access** | Restricted by policy | **Global** (user-level) |
| **Write Access** | Restricted to Workspace | Restricted to Workspace |
| **Security Level** | Production-ready | **Experimental / Prototype** |

## Usage & Default Behavior

The macOS sandbox is **disabled by default** to avoid dependency on legacy system tools unless explicitly requested.

- **Feature Flag**: You must enable the `macos-sandbox` feature in `agent-guard-sandbox` or `agent-guard-sdk`.
- **Availability Detection**: Even with the feature enabled, `SeatbeltSandbox` is only considered available when `sandbox-exec` is functional on the current host.
- **Default Fallback**: If the feature is not enabled, or if running on a non-Linux/macOS platform, the `Guard::execute_default()` API will fall back to `NoopSandbox` (no OS-level isolation).
- **Manual Execution**: You can always manually instantiate `SeatbeltSandbox` if the feature is enabled.

## Security Recommendation

For macOS deployments, we recommend:
1. Using the sandbox in conjunction with **strict policy allowlists** and **comprehensive audit logging**.
2. Never treating the `SeatbeltSandbox` as a sufficient standalone security boundary.
3. Complementing it with user-level permissions (running the agent under a dedicated, restricted system user).

## Implementation Details

The sandbox generates a Scheme-style profile at runtime:

```lisp
(version 1)
(deny default)
(allow file-read*)
(allow file-write* (subpath "/path/to/workspace"))
(allow process-fork)
(allow process-exec)
(deny network*)
```

## Future Work

To reach parity with the Linux implementation, future versions of the macOS sandbox will need to:
- Move to the modern **App Sandbox** (App Sandbox entitlement) or **Endpoint Security framework**, though these typically require code signing and are less suitable for CLI tools.
- Reduce the current global-read posture once a stable set of "base" paths (e.g., `/usr/lib`, `/System/Library`) is identified.
