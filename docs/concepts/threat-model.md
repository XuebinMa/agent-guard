# 🏹 Threat Model

| Field | Details |
| :--- | :--- |
| **Status** | 🟠 Active Review (current source) |
| **Audience** | Security Auditors, Compliance Officers |
| **Version** | 2.4 |
| **Last Reviewed** | 2026-10-06 |
| **Related Docs** | [Enforcement Layers (ADR)](enforcement-layers.md), [Capability Parity](capability-parity.md), [Archive: Architecture & Future Directions](../archive/architecture-and-vision.md) |

---

> This document separates current decision/execution checks from deployment requirements. The focused boundary is an exact brokered Git transaction; a same-user installation and the default noop executor are not credential isolation.

---

## 1. 🏗️ Asset Inventory

The agent may control checkout contents, commits, tool inputs and its own
container processes. Its explanation or staged plan is not trusted authorization.
The host kernel/runtime, broker/Git binaries, dedicated authentication programs,
host config and approving terminal are trusted computing base. The first profile
does not promise containment of a compromised host, a malicious human approver
or every possible non-Git data-export path.

These are assets a deployment must protect, not guarantees supplied by the SDK
alone. The [credential-isolation guide](../guides/operations/credential-isolation.md)
maps read, write and use authority for the first planned container profile.

| Asset | Importance | Security Requirement |
| :--- | :--- | :--- |
| **Policy Files (`policy.yaml`)** | **CRITICAL** | **Integrity**: Unauthorized modification leads to complete bypass. Must be protected by OS-level permissions. |
| **Audit Logs (JSONL)** | **HIGH** | **Integrity / Availability**: Logs should be preserved for investigations, but local JSONL alone is not cryptographic non-repudiation. |
| **Host System (Kernel/FS)** | **CRITICAL** | **Isolation**: Keep the unprivileged agent inside the chosen runtime boundary. Host kernel/runtime correctness is trusted, not a property proven by a command validator. |
| **Secrets (Env/SSH Keys)** | **CRITICAL** | **Confidentiality**: Prevent unauthorized reading or exfiltration of sensitive developer credentials. |
| **Network (Local/External)** | **HIGH** | **SSRF Prevention**: Prevent internal network scanning and unauthorized command-and-control (C2) communication. |
| **Telemetry Data** | **MEDIUM** | **Availability**: Real-time monitoring data must persist even if an agent process crashes or is compromised. |
| **Broker Grants and Host Credentials** | **CRITICAL** | **Integrity / Isolation**: A grant binds the exact push transaction and is consumed before execution-stage network access. Preview may query a permitted remote before approval. Config, grants, credentials, sockets and helper invocation must be outside agent read/write/use authority. |

---

## 2. 🏹 Attack Surface Matrix
Mapping potential entry points and their mitigation strategies:

| Surface Component | Entry Vector | Potential Impact | Mitigation Strategy |
| :--- | :--- | :--- | :--- |
| **Tool Payloads** | Malicious JSON/CLI args | Unintended action, command execution | Strict payload validation, policy rules and bounded Bash AST classification; arbitrary-program effects still require deployment containment. |
| **Filesystem Access** | Path traversal, Symlinks | Data exfiltration, Overwrite | Glob-based Allow/Deny paths + platform sandbox isolation (Landlock/Seatbelt/Windows token model). |
| **Network Stack** | Outbound HTTP/Socket | Data exfiltration, SSRF | Policy-level URL/path controls + platform sandboxing where available. |
| **Process Management** | Fork-bomb, child escape | DoS, Sandbox Escape | Job Objects (Windows) / cgroups (Linux Planned). |
| **Config Loader** | Malicious YAML config | Engine DoS, Logic Bypass | AOT Validation + Type-safe parsing + Schema enforcement. |
| **Git Push Broker** | Mutable repository config, hooks, objects, refs | Credential theft, redirecting an approved push | Exact approved URL/OID, grant claim before execution-stage network, isolated temporary repository, sanitized Git configuration/environment, and remote lease revalidation. Preview can query a scoped destination before approval. |
| **Decision-only Hook** | Missing/stale binary, bypassable host hook | Action proceeds without containment | Explicit fail-open advisory contract, exact plugin/binary version check, and a host-owned runtime boundary covering all tools, not only shell execution. |

---

## 3. 🛡️ STRIDE Threat Analysis (v2.2 Refined)
Categorized analysis of threats and implemented defenses:

### **S**poofing (Identity)
- **Threat**: An unauthorized agent or actor impersonates a trusted one in the `Context`.
- **Mitigation**: The trusted host orchestrator is responsible for providing
  immutable, authenticated, and bounded `actor`, `agent_id`, and `session_id`
  values. The SDK cannot distinguish a host-authenticated identity from a string
  copied out of an agent-controlled payload.

### **T**ampering (Integrity)
- **Threat**: An agent modifies the security policy or deletes its own audit logs.
- **Mitigation**: **Out of scope for SDK** — requires OS-level file permissions (e.g., `chmod 400` on policy files).

### **R**epudiation (Non-repudiability)
- **Threat**: An attacker claims they did not execute a destructive command.
- **Mitigation**: Structured unsigned JSONL audit logs for forensic review. The
  SDK can sign `ExecutionReceipt` values with an explicit key. The broker library
  has a separate optional signing API; the current `agent-guard push` CLI creates
  unsigned `PushReceipt` values and persists them only with `--receipt`, after
  entering execution. Early policy refusals, preview failures and cancellation
  do not produce a broker execution receipt. None proves credential isolation.

### **I**nformation Disclosure (Confidentiality)
- **Threat**: An agent reads host secrets (e.g., `.ssh/id_rsa`) via a `read_file` tool call.
- **Mitigation**: Deny-path rules for modeled file operations, plus a deployment
  that does not expose secrets through mounts, environment, sockets or tools.
  `ReadOnly` limits writes; it does not mean "cannot read host credentials".
  Current sandbox capabilities do not provide global read isolation.

### **D**enial of Service (Availability)
- **Threat**: An agent exhausts CPU/RAM or initiates a rapid-fire loop of tool calls.
- **Mitigation**: **Anomaly Detection** (frequency-based), a five-minute
  default for Guard-owned Bash, a 4 MiB per-stream output cap, Unix
  process-group cleanup, and Windows Job Object process/memory limits (256MB
  default). Guard-owned HTTP also caps response bodies at 4 MiB and admits at
  most 64 in-flight requests per process, failing before DNS when saturated.
  Process groups are not cgroups/PID namespaces; a hostile executable
  that can deliberately leave its group still requires a stronger host
  containment boundary.

### **E**levation of Privilege (Isolation)
- **Threat**: An agent escapes the sandbox to gain root/Administrator privileges.
- **Mitigation**: Run the agent unprivileged in the chosen host/container
  boundary. Low-IL/Job Object, Seatbelt and Landlock provide their documented
  resource restrictions, not a general guarantee against kernel/runtime
  privilege escalation. Their availability and mode-specific coverage must be
  checked independently.

---

## 🛡️ Active Boundary Map

| Execution shape | Enforced property | Not established by this shape |
| :--- | :--- | :--- |
| **Decision-only hook / `check` / `decide`** | Policy decision and unsigned audit record; the host may honor the decision. | OS containment, credential isolation, or signed execution evidence. The Claude Code hook deliberately fails open on integration faults. |
| **Git push broker** | Exact URL/OID transaction, one-use execution grant, isolated Git execution and remote lease. CLI receipts are unsigned and stored only with `--receipt`. | Credential isolation or human caller identity when the agent can read/write/use broker resources or invoke the credential-bearing CLI itself. |
| **Guard-owned execution with `NoopSandbox`** | Policy decision, bounded process/output lifecycle, and execution records. | OS filesystem, network, syscall, or privilege containment. |
| **Linux seccomp** | Opt-in native BPF syscall filtering in restricted modes; required rules fail closed. `FullAccess` deliberately skips filtering. | Path-aware workspace writes, global read or credential isolation; use the appropriate filesystem/runtime boundary for those properties. |
| **Linux Landlock (ABI v3+)** | Read-only or workspace-scoped filesystem writes according to `PolicyMode`. | Network restriction, global read restriction, PID namespace, or cgroup limits. |
| **macOS Seatbelt** | Best-effort workspace writes and network denial when the runtime probe succeeds. | Global read restriction or a supported long-term Apple sandbox API. |
| **Windows Low-IL Job Object** | Protected-location write denial, resource/process lifetime controls when the runtime probe succeeds. | Network restriction, global read restriction, or a precise workspace allowlist. |
| **Windows AppContainer** | Nothing: this backend is disabled and returns unavailable. | Any AppContainer containment claim until exact DACL restoration and handle ownership are proven in Windows tests. |

---

## 🔪 Known Sharp Edges (Operator Guidance)

Some entries are configuration-dependent behavior; others are unresolved
limitations. Each states the behavior and a deployment mitigation. Open risks,
including hard-link aliases and Windows inherited handles, are not repairs or
validation completed by this document.

### 1. The default build ships no OS-level syscall/network isolation
Platform sandbox features (`seccomp`, `landlock`, `macos-sandbox`,
`windows-sandbox` / `windows-appcontainer`) are **off by default**. In a default
build the sandbox layer is a passthrough shell, so policy + validators provide
only an agent-guard decision gate, not OS containment. This is reported truthfully by
`Guard::default_sandbox_diagnosis()` (`selected = "none"`, `fallback_to_noop =
true`, or `selected = "seccomp"` only when the filter is actually compiled in).
- **Recommended**: compile with the platform feature for defense-in-depth, run as
  a low-privilege user, and never assume "sandbox" enforcement is active unless
  the diagnosis confirms it.

### 2. `working_directory` must be set for `ReadOnly` / `WorkspaceWrite`
The implicit "everything outside the workspace is denied" fence is derived from
`context.working_directory`. If you leave it unset, that implicit fence is absent
— explicit `deny_paths` / `allow_paths` still apply, but the workspace bound does
not.
- **Recommended**: always populate `working_directory` for confinement-bearing
  modes, or pin scope explicitly with `allow_paths`.

### 3. Untrusted callers ignore tool-level `mode` (by design)
`effective_mode` deliberately ignores a tool's `mode` for `Untrusted` so a
tool-level `full_access` cannot **escalate** an untrusted agent (locked by the
`untrusted_ignores_tool_level_full_access_override` test). The same applies to
**tightening**: a tool `mode: read_only` does not further restrict an untrusted
caller either.
- **Recommended**: to restrict a tool for untrusted callers, use `default_mode`,
  `trust.untrusted.override_mode`, or explicit `deny` rules — not the tool's
  `mode`.

### 4. `allow` rules match by substring
A plain `allow` pattern matches when the value *contains* it anywhere, so
`plain: "ls"` would allow `rm -rf / # ls`. Deny-by-substring is safe (it
over-matches), but allow-by-substring can leak permission.
- **Recommended**: anchor `allow` rules with `prefix:` or `regex:` (e.g.
  `regex: '^ls( |$)'`), never a bare substring.

### 5. `check_destructive` is a warning, not a boundary
The destructive-command list raises an `ask`, not a `deny`, and is a best-effort
mix of literal substring patterns and parsed command-name checks. Literal
patterns both over- and under-match; they do not model every command effect.
- **Recommended**: do not treat the destructive warning as enforcement; rely on
  the relevant decision checks and actual backend/deployment resource boundary.
  Mode/path classification alone is not arbitrary-code confinement.

### 6. Shell classification is an intent gate, not arbitrary-code containment
The parser uses `tree-sitter-bash` for a bounded set of static syntax and argument
shapes. Unix runners execute `sh -c`; Windows noop/Job Object runners execute
`cmd.exe /C`, while a hook leaves execution dialect to its host. These are not
equivalent interpreters. Restricted modes refuse known unsupported syntax and
opaque launchers; `ReadOnly` uses an executable allowlist, but `WorkspaceWrite`
does **not** refuse every unknown program. Even a recognized binary can use
environment, plugins, helpers or configuration that the classifier does not
model. Workspace path checks also cannot eliminate concurrent-process races.
- **Recommended**: treat validator decisions as defense in depth and activate a
  platform sandbox when arbitrary code can run. Assert the selected backend and
  its capabilities at startup; do not describe `WorkspaceWrite` shell parsing
  alone as filesystem containment.

### 7. Anomaly lockout is only as strong as the subject identity
The deny fuse chooses a subject from `actor`, then `agent_id`, then `session_id`.
Missing identities share one fail-closed `unknown` subject. If an agent can
choose or rotate those strings, it can evade a per-subject threshold; if it can
make them arbitrarily large, it can also amplify state and telemetry costs.
Locked subjects are deliberately not evicted by ordinary capacity compaction.
- **Recommended**: derive one stable, size-bounded subject in the trusted host
  adapter and never accept it from model output. If the host cannot authenticate
  that value, describe anomaly detection as advisory rate limiting, not
  per-agent lockout protection.

### 8. Broker isolation is a deployment property
The push broker removes repository hooks/config from its temporary execution
repository and binds execution to the approved push URL. That does not protect a
credential or helper the agent can access directly. `PATH`, `HOME`/SSH config,
the dedicated broker Git config, `SSH_AUTH_SOCK`, signing keys and the broker
binary are part of the host trusted computing base.
- **Recommended**: keep those resources outside the agent-readable/writable
  and usable boundary, including authentication and container-management
  sockets. Use a host-owned broker process, and follow the independent checks
  in [Credential isolation](../guides/operations/credential-isolation.md).

The first strict deployment profile is **planned**, not yet accepted: one Linux
host, an existing unprivileged container runtime, one normal repository, an
authenticated HTTPS remote and an ordinary non-force branch push. All agent
tools, file access, MCP servers and hooks must remain inside that boundary.
Existing SSH/SCP and macOS/Windows APIs are not removed; they are outside this
first deployment acceptance claim. `guard-verify doctor` reports local
capabilities, not credential isolation or approving-principal identity.

### 9. Directory authority does not separate hard-linked aliases
The capability-relative `WriteFile` executor prevents path/symlink traversal,
but a pre-existing regular file can have another hard link outside the workspace.
Writing that inode also changes its other names. This is not prevented by checking
the final path, and a pre-open link-count check alone would introduce another race.
- **Recommended**: do not share writable inodes between a hostile workspace and
  trusted host data. Use a separate filesystem or copy-based staging. Atomic
  replacement semantics for overwrite/append require a separate compatibility
  design before claiming alias isolation.

### 10. Windows inherited handles remain a review item
The experimental Job Object launcher currently enables handle inheritance without
an explicit handle allowlist. A parent handle deliberately marked inheritable can
carry authority not granted by the child's restricted token. The current unit
test checks non-inheritable defaults, not that adversarial case.
- **Recommended**: do not treat this backend as an ambient-handle isolation
  boundary until a `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` launch path and a real
  Windows child-handle regression pass. This was source-reviewed on macOS, not
  demonstrated on a Windows host; see the [review](../security-review-2026-10-04.md).

### 11. Cancelling a Python waiter is not cancelling a host action
A synchronous host callback running in a worker thread may continue after its
asyncio waiter is cancelled. The worker reports its actual terminal result, not
a premature failure attributed to cancellation. Process exit can still interrupt
reporting. Native Guard calls release the GIL, but that does not make arbitrary
host code cancellable.
- **Recommended**: use cooperative cancellation or an independently managed
  process for host work that must be stopped; do not retry on cancellation alone.

---

## 🛠️ Security Hardening Checklist

1. [ ] **Low-Privilege User**: Never run `agent-guard` as `root` or `Administrator`.
2. [ ] **Fail-Closed Config**: Verify that `Guard::execute()` errors are handled as hard failures.
3. [ ] **Audit Offloading**: Send JSONL logs to a write-only remote destination.
4. [ ] **Metric Alerts**: Set alerts in Grafana for `agent_guard_anomaly_triggered_total > 0`.
5. [ ] **Confirm Sandbox Backend**: At startup, assert `default_sandbox_diagnosis().fallback_to_noop == false` if you require OS-level isolation (see Sharp Edge #1).
6. [ ] **Set Workspace Bound**: Populate `context.working_directory` for `ReadOnly` / `WorkspaceWrite`, or constrain scope with `allow_paths` (Sharp Edge #2).
7. [ ] **Anchor Allow Rules**: Prefer `prefix:` / `regex:` over bare-substring `allow` patterns (Sharp Edge #4).
