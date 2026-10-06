# 🗺️ Capability Parity Matrix

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Current source baseline |
| **Audience** | DevOps, Security Engineers |
| **Version** | 1.3 |
| **Last Reviewed** | 2026-10-02 |
| **Related Docs** | [Threat Model](threat-model.md), [Archive: Architecture & Future Directions](../archive/architecture-and-vision.md) |

---

> This document defines the security baseline for the Unified Capability Model (UCM). It serves as a transparent record of what is enforced vs. what remains as a known gap on each platform.
>
> The matrix below reflects static sandbox-level capability metadata. A
> specific execution can still be stricter than the matrix when the active
> `PolicyMode` tightens behavior at runtime.
> Runtime availability is a separate concern: if a backend fails its host checks,
> `CapabilityDoctor` now reports it as unavailable and the SDK may explicitly
> fall back to `NoopSandbox`.
> That fallback preserves the logic-layer policy gate, but it does **not** preserve equivalent OS-level isolation.

---

## 📊 Static capability metadata

| **UCM Capability** | **Linux Seccomp** | **Linux Landlock** | **macOS Seatbelt** | **Windows Low-IL** | **AppContainer** | **Noop** |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`filesystem_read_workspace`** | ✅ | ✅ | ✅ | ✅ | Disabled | ✅ |
| **`filesystem_read_global`** | ✅ | ✅ | ✅ | ✅ | Disabled | ✅ |
| **`filesystem_write_workspace`** | ✅ | ✅ | ✅ | ✅ | Disabled | ✅ |
| **`filesystem_write_global`** | ❌ Allowed | ❌ Allowed | 🛡️ Blocked | 🛡️ Blocked | Disabled | ❌ Allowed |
| **`network_outbound_any`** | ❌ Allowed | ❌ Allowed | 🛡️ Blocked | ❌ Allowed | Disabled | ❌ Allowed |
| **`network_outbound_internet`**| ❌ Allowed | ❌ Allowed | 🛡️ Blocked | ❌ Allowed | Disabled | ❌ Allowed |
| **`child_process_spawn`** | ✅ | ✅ | ✅ | ✅ | Disabled | ✅ |
| **`registry_write`** | N/A | N/A | N/A | 🛡️ Blocked | Disabled | ❌ Allowed |

**Legend**:
- ✅ **Allowed**: Intentionally permitted by the sandbox.
- 🛡️ **Blocked**: Successfully intercepted and denied by OS-level enforcement.
- ❌ **Allowed**: Unintentionally permitted (security gap or non-goal for that platform).
- **N/A**: Not applicable to the platform.

The two Linux backends report global write/network availability because this
metadata spans every `PolicyMode`: `FullAccess` intentionally permits them.
Execution-time behavior is stricter. Seccomp blocks networking in
`ReadOnly`/`WorkspaceWrite` and common writes in `ReadOnly`; it remains
path-agnostic in `WorkspaceWrite`. Landlock blocks all writes in `ReadOnly` and
grants the ABI-v3 write set only below the workspace in `WorkspaceWrite`, but
does not restrict networking. The macOS Seatbelt profile is mode-specific in the
same way: it grants writes below the workspace in `WorkspaceWrite` and
`FullAccess`, and none but `/dev/null` in `ReadOnly`. Do not infer per-call
guarantees from this static table; use the active backend, mode and OS
integration tests together.

---

## 🛡️ Security Boundaries (Platform Summary)

| Platform | What this protects | What this does not protect |
| :--- | :--- | :--- |
| **Linux** | Native Seccomp-BPF filtering for read-only and workspace-write executions, or path-aware mode-specific write isolation with Landlock ABI v3+. | Seccomp alone cannot enforce workspace paths; Landlock does not restrict networking or global reads. Backend selection is explicit: neither silently combines with the other. |
| **macOS** | Workspace write isolation via Seatbelt profiles. | Global read access (Prototype limit). |
| **Windows** | Integrity-based write protection (Low-IL Job Object) when its runtime probe succeeds. | Network access in Low-IL mode. The AppContainer prototype is disabled because it cannot yet prove exact workspace-DACL restoration. |

---

## ⚠️ Known Gaps & Roadmap

1. **Windows Network Isolation (Low-IL)**: The Low-IL backend does not restrict network access. The `windows-appcontainer` feature currently exposes a disabled, fail-closed placeholder: the earlier prototype replaced the workspace DACL and could not prove restoration on every exit path. Requesting it resolves to `none` (or the default resolver selects a functional Low-IL Job Object when that feature is also present) until Windows CI locks exact DACL preservation.
2. **macOS Global Read**: The Seatbelt profile still emits `(allow file-read* (subpath "/"))`, so reads outside the workspace are intentionally permitted at the OS layer. Future iterations will tighten this to `(allow file-read* (subpath workspace))`. Until then, treat macOS as a write-confinement backend, not a read-confinement one.
3. **Linux FS Isolation**: Native seccomp blocks common write and networking syscalls in restricted modes but is path-agnostic. A path-aware **Landlock** backend (`landlock` feature) is shipped and is the recommended choice when you need OS-level workspace-only write isolation. It now requires Landlock ABI v3 (upstream Linux 6.2+) so `truncate`, `ftruncate`, and `O_TRUNC` are part of the enforced boundary. Hosts without ABI v3 fall back truthfully to the next available backend plus the in-process validator gate.
