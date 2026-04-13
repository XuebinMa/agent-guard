# Windows Experimental Sandbox: Job Objects (`windows-sys`)

The Windows sandbox implementation in `agent-guard` is an **experimental prototype** based on Windows Job Objects (via the `windows-sys` crate).

**Important**: This is not equivalent to the Linux seccomp sandbox and should not be treated as the same security boundary.

## ⚠️ Threat Model & Limitations

While the Linux implementation uses `seccomp-bpf` for fine-grained syscall filtering, the Windows Job Object implementation is currently a **resource-oriented prototype** with significant security limitations:

1.  **Process-only Isolation**: Job Objects primarily control resource limits (CPU, memory, handle counts) and process lifetimes. They do not natively provide fine-grained filesystem or network filtering without additional components (like AppContainers or Low Integrity Levels).
2.  **Permissive Network Policy**: The current prototype does **no network isolation**. Windows Firewall or other system-level filtering is required to block network access.
3.  **Coarse Filesystem Controls**: The current prototype strengthens containment with a Low Integrity Level (Low-IL) token, which blocks writes to protected medium/high integrity locations such as `C:\Windows`. However, this is still much coarser than Linux path-level mediation and does not yet provide a first-class workspace allowlist.
4.  **Global Read Access**: Low-IL does not prevent the sandboxed process from reading files the user can already read.
5.  **No Syscall Filtering**: Windows does not have a native equivalent to Linux Seccomp that is easily accessible to CLI tools. Restricting syscalls would require kernel-mode drivers or complex user-mode hooking.

## Comparison: Linux vs. Windows (Prototype)

| Feature | Linux (Seccomp) | Windows (Job Object) |
|---|---|---|
| **Primary Goal** | Syscall-level Hardening | Resource & Lifetime Management |
| **Network** | Blocked by default | **Allowed** (current prototype) |
| **Read Access** | Restricted by policy | **Global** (user-level) |
| **Write Access** | Restricted to Workspace | Protected global writes blocked by Low-IL |
| **Security Level** | Production-ready | **Experimental / Strengthened Prototype** |

## Phase 5: Hardening Roadmap (Current)

The current Windows implementation is a **Verifiable Prototype**. In Phase 5, we are focused on moving toward a **Stronger Prototype** with better isolation.

### 1. Low-Integrity Level (Low-IL) Token (P0)
- **Status**: **Implemented & Active**.
- **Implementation**: Restricts the sandboxed process to a Low Integrity Level (SID `S-1-16-4096`). This prevents the process from writing to medium/high integrity folders (e.g., `C:\Windows`, `C:\Users\Admin`) even if the user account has permissions.

### 2. AppContainer Isolation (P0 - Research)
- **Goal**: Use the modern Windows AppContainer framework for fine-grained capability and filesystem isolation.
- **Feasibility**: Requires complex SID management and capability registration. We are currently researching a 'CLI-friendly' AppContainer prototype that doesn't require full UWP registration.

### 3. Fail-Closed behavior for all Win32 API calls (P0)
- **Goal**: Ensure that if `AssignProcessToJobObject` or any token-restricted call fails, the entire tool execution is aborted.
- **Status**: Currently implemented for Job Objects. This will be extended to Low-IL token creation.

### 4. Windows-Specific Integration Tests (P0)
- **Status**: **Implemented & Active**.
- **Implementation**: Dedicated Windows CI now runs `windows_job_integration` to verify Job Object availability, working-directory application, and protected-directory write blocking.

## Use Cases

### Suitable for:
- Local development and testing on Windows.
- Basic resource limiting (preventing fork-bombs or memory exhaustion).
- Ensuring child processes are cleaned up when the agent exits.
- Blocking writes to protected system directories with Low-IL.

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
- Add a true workspace-scoped write model instead of relying on coarse Low-IL behavior alone.
- Implement **AppContainer** for stronger filesystem and capability isolation.
- Use **Windows Filtering Platform (WFP)** for network restriction.
- Investigate **Runtime Broker** patterns for mediated access to system resources.
