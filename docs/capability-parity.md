# 🗺️ Capability Parity Matrix

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Baseline Established (v0.2.0) |
| **Audience** | DevOps, Security Engineers |
| **Version** | 1.1 |
| **Last Reviewed** | 2026-04-08 |
| **Related Docs** | [Architecture & Vision](architecture-and-vision.md), [Threat Model](threat-model.md) |

---

> This document defines the security baseline for the Unified Capability Model (UCM). It serves as a transparent record of what is enforced vs. what remains as a known gap on each platform.

---

## 📊 Parity Matrix (v0.2.0 Baseline)

| **UCM Capability** | **Linux (Seccomp)** | **macOS (Seatbelt)** | **Windows (Low-IL)** | **Windows (AppContainer)** | **Noop (None)** |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`filesystem_read_workspace`** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **`filesystem_read_global`** | ✅ | ✅ | ✅ | 🛡️ Blocked | ✅ |
| **`filesystem_write_workspace`** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **`filesystem_write_global`** | 🛡️ Blocked | 🛡️ Blocked | 🛡️ Blocked | 🛡️ Blocked | ❌ Allowed |
| **`network_outbound_any`** | 🛡️ Blocked | 🛡️ Blocked | ❌ Allowed | 🛡️ Blocked | ❌ Allowed |
| **`network_outbound_internet`**| 🛡️ Blocked | 🛡️ Blocked | ❌ Allowed | ✅ Allowed | ❌ Allowed |
| **`child_process_spawn`** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **`registry_write`** | N/A | N/A | 🛡️ Blocked | 🛡️ Blocked | ❌ Allowed |

**Legend**:
- ✅ **Allowed**: Intentionally permitted by the sandbox.
- 🛡️ **Blocked**: Successfully intercepted and denied by OS-level enforcement.
- ❌ **Allowed**: Unintentionally permitted (security gap or non-goal for that platform).
- **N/A**: Not applicable to the platform.

---

## 🛡️ Security Boundaries (Platform Summary)

| Platform | What this protects | What this does not protect |
| :--- | :--- | :--- |
| **Linux** | Syscall-level hardening, global filesystem write protection. | Fine-grained path-level read restriction (Landlock planned). |
| **macOS** | Workspace write isolation via Seatbelt profiles. | Global read access (Prototype limit). |
| **Windows** | Integrity-based write protection (Low-IL) or SID-based isolation (AppContainer). | Network access in default Low-IL mode. |

---

## ⚠️ Known Gaps & Roadmap

1. **Windows Network Isolation**: Currently, Low-IL does not restrict network access. This is a primary driver for the **AppContainer (M7.1)** implementation.
2. **macOS Global Read**: The Seatbelt prototype currently allows reading files outside the workspace. Future iterations will tighten this to `(allow file-read* (subpath workspace))`.
3. **Linux FS Isolation**: While Seccomp blocks writes globally, it does not currently provide a virtualized or restricted view of the filesystem. Integration with **Landlock** or **Mount Namespaces** is planned for v0.3.0.
