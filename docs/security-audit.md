# Security Audit & Risk Ledger — agent-guard

> Status: **Pre-release Audit (Phase 7)**  
> Version: **0.2.0-Audit.1**  
> This report summarizes the findings of the final security self-audit before the v0.2.0 release.

---

## 1. 🏗️ Summary of Audit Activities
- **Dependency Review**: Manual check of `Cargo.toml` for supply chain risks.
- **`unsafe` Block Audit**: Focused on memory safety and handle management in Win32 implementations.
- **Handle/Token Lifecycle**: Verified RAII usage for OS resources.
- **Key Management**: Reviewed provenance receipt signing boundaries.
- **Platform Capability Verification**: Cross-platform parity integration tests.

---

## 2. 🛡️ Findings & Remediations

| ID | Component | Severity | Description | Status |
| :--- | :--- | :--- | :--- | :--- |
| **AUDIT-01** | `windows.rs` | **Medium** | Potential handle leak in `create_low_integrity_token` if SID allocation fails. | ✅ Fixed (RAII) |
| **AUDIT-02** | `linux.rs` | **High** | Seccomp-BPF implementation is currently a placeholder; parity tests will fail on Linux. | ⚠️ Flagged (M7.2) |
| **AUDIT-03** | `provenance.rs`| **Low** | Private keys for receipt signing are passed by reference; risk of accidental exposure in logs. | ℹ️ Recommended (Zeroize) |
| **AUDIT-04** | Handle Audit | **Low** | `read_handle_to_string` relies on parent closing the handle; potential confusion in ownership. | ℹ️ Monitored |

---

## 3. 🔍 Deep Dive: `unsafe` Review (Win32)

The `agent-guard-sandbox` crate on Windows makes extensive use of Win32 APIs via `windows-sys`.  
**Current Posture**:
- Every critical handle (`hProcess`, `hThread`, `hJob`, `hToken`, `hPipe`) is wrapped in a `SafeHandle` or `JobHandle` struct implementing `Drop`.
- `CreateProcessAsUserW` is called with `CREATE_SUSPENDED` to ensure the process is assigned to a Job Object before it can execute any code.
- Handle inheritance is explicitly restricted to only the `Write` end of Stdout/Stderr pipes.

---

## 4. 🔑 Provenance Key Management

- **Current Implementation**: `ExecutionReceipt::sign` accepts an `ed25519_dalek::SigningKey`.
- **Boundary**: The SDK does not manage key storage (KMS/Vault). It is the responsibility of the host application to provide the key.
- **Risk**: If the host application is compromised, the signing key can be stolen to forge receipts.
- **Mitigation**: Recommend using a Hardware Security Module (HSM) or transient, short-lived signing keys.

---

## 5. 🛡️ Security Baseline (v0.2.0)

- **Linux**: Seccomp-BPF (Implementation pending restoration).
- **macOS**: Seatbelt (Canonical path resolution enforced).
- **Windows**: Low-IL (Handle inheritance audit passed).
- **All Platforms**: Ed25519 Signed Receipts for all executions.
