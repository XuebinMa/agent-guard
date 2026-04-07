# Windows Experimental Sandbox: Job Objects (`windows-sys`)

The Windows sandbox implementation in `agent-guard` is an **experimental prototype** based on Windows Job Objects (via the `windows-sys` crate).

**Important**: This is not equivalent to the Linux seccomp sandbox and should not be treated as the same security boundary.

## ⚠️ Threat Model & Limitations

While the Linux implementation uses `seccomp-bpf` for fine-grained syscall filtering, the Windows Job Object implementation is currently a **resource-oriented prototype** with significant security limitations:

1.  **Process-only Isolation**: Job Objects primarily control resource limits (CPU, memory, handle counts) and process lifetimes. They do not natively provide fine-grained filesystem or network filtering without additional components (like AppContainers or Low Integrity Levels).
2.  **Permissive Network Policy**: The current prototype does **no network isolation**. Windows Firewall or other system-level filtering is required to block network access.
3.  **Global Read/Write Access**: Unlike Linux Seccomp which can block `write` syscalls based on paths, Job Objects do not restrict filesystem access. The current prototype relies on the user's system-level permissions.
4.  **No Syscall Filtering**: Windows does not have a native equivalent to Linux Seccomp that is easily accessible to CLI tools. Restricting syscalls would require kernel-mode drivers or complex user-mode hooking.
5.  **Breakaway Prevention**: The job object is configured with `JOB_OBJECT_LIMIT_BREAKAWAY_OK` (currently) to allow child processes to escape the job if necessary for some developer tools, which reduces security.

## Comparison: Linux vs. Windows (Prototype)

| Feature | Linux (Seccomp) | Windows (Job Object) |
|---|---|---|
| **Primary Goal** | Syscall-level Hardening | Resource & Lifetime Management |
| **Network** | Blocked by default | **Allowed** (current prototype) |
| **Read Access** | Restricted by policy | **Global** (user-level) |
| **Write Access** | Restricted to Workspace | **Global** (user-level) |
| **Security Level** | Production-ready | **Experimental / Prototype** |

## Use Cases

### Suitable for:
- Local development and testing on Windows.
- Basic resource limiting (preventing fork-bombs or memory exhaustion).
- Ensuring child processes are cleaned up when the agent exits.

### NOT suitable for:
- Handling highly sensitive secrets.
- Hostile multi-tenant execution.
- Strong exfiltration resistance.

## Usage & Default Behavior

The Windows sandbox is **disabled by default** and requires a feature flag.

- **Feature Flag**: You must enable the `windows-sandbox` feature in `agent-guard-sandbox` or `agent-guard-sdk`.
- **Default Fallback**: If the feature is not enabled, or if running on a non-Linux/macOS/Windows platform, the `Guard::execute_default()` API will fall back to `NoopSandbox`.

## Setup & Configuration

To use the Windows sandbox in your project:

1.  **Enable the feature** in your `Cargo.toml`:
    ```toml
    [dependencies]
    agent-guard-sdk = { version = "0.1", features = ["windows-sandbox"] }
    ```
2.  **Initialize the Guard**:
    ```rust
    let guard = Guard::from_yaml("version: 1")?;
    // On Windows, this will now automatically use JobObjectSandbox
    let outcome = guard.execute_default(&input)?;
    ```

## Known Win32 API Limitations

- **`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`**: Used to ensure that if the agent or orchestrator crashes, all sandboxed tool processes are immediately terminated by the Windows kernel.
- **Job Object Nesting**: On older Windows versions (pre-Windows 8), Job Objects cannot be nested. This implementation assumes a modern Windows environment where nesting is supported.

## Security Recommendation

For Windows deployments, we recommend:
1. Running the agent under a **dedicated, low-privileged service account**.
2. Using the sandbox in conjunction with **strict policy allowlists** and **comprehensive audit logging**.
3. Complementing it with Windows Firewall rules to block network access if needed.

## Future Work

To reach parity with the Linux implementation, future versions of the Windows sandbox will need to:
- Implement **AppContainer** or **Low Integrity Levels (Low-IL)** for filesystem and network isolation.
- Use **Windows Filtering Platform (WFP)** for network restriction.
- Investigate **Runtime Broker** patterns for mediated access to system resources.
