# Capability Parity Matrix — agent-guard

> Status: **Baseline Established / Gaps Documented (v0.2.0)**  
> Version: **1.0**  
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

## 🔍 Verification Methodology

Parity is verified using the unified integration test suite located at `crates/agent-guard-sdk/tests/parity.rs`.  
To run the verification on your current platform:

```bash
# Linux
cargo test --test parity --features seccomp

# macOS
cargo test --test parity --features macos-sandbox

# Windows
cargo test --test parity --features windows-sandbox
```

---

## ⚠️ Known Gaps & Roadmap

1. **Windows Network Isolation**: Currently, Low-IL does not restrict network access. This is a primary driver for the **AppContainer (M7.1)** implementation.
2. **macOS Global Read**: The Seatbelt prototype currently allows reading files outside the workspace. Future iterations will tighten this to `(allow file-read* (subpath workspace))`.
3. **Linux FS Isolation**: While Seccomp blocks writes globally, it does not currently provide a virtualized or restricted view of the filesystem. Integration with **Landlock** or **Mount Namespaces** is planned for v0.3.0.
