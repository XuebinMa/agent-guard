# Windows AppContainer Feasibility Research (M6.2)

> Status: **Completed**  
> This document summarizes the findings from the feasibility spike for implementing AppContainer-based isolation on Windows for `agent-guard`.

---

## 1. 🛠️ API & Core Logic
AppContainer isolation is achieved via the following Win32 APIs:
- `CreateAppContainerProfile`: Creates a persistent profile for the user.
- `DeriveAppContainerSidFromAppContainerName`: Gets the SID for a profile.
- `GetAppContainerFolderPath`: Finds the profile's local storage folder.
- `CreateProcessAsUserW` (or `CreateProcessW` with a prepared token): Launches the process.

### Launch Sequence:
1. Get/Create AppContainer Profile.
2. Grant the AppContainer SID (and `ALL_APPLICATION_PACKAGES`) access to the workspace directory via `SetNamedSecurityInfo`.
3. Create a restricted token with the AppContainer SID.
4. Add desired capabilities (e.g., `internetClient`) to the token.
5. Launch process via `CreateProcessAsUserW` inside a Job Object.

---

## 2. ❓ Research Questions & Answers

### Q1: Is AppContainer the default?
**Answer**: **No.** AppContainer requires profile management and ACL manipulation on the filesystem, which is more "invasive" than Low-IL. It will be an **opt-in** feature for v0.2.0.

### Q2: Feature Flag?
**Answer**: **Yes.** Controlled via `windows-appcontainer` feature flag to avoid pulling in extra `windows-rs` dependencies for basic users.

### Q3: Coexistence with Low-IL?
**Answer**: AppContainer processes are inherently restricted. We will use AppContainer SIDs as the primary boundary. Job Objects will remain for **resource limits** and **process tree cleanup**.

### Q4: Initial Capabilities?
**Answer**:
- `filesystem_write_workspace`: Granting ACLs to the AppContainer SID.
- `network_outbound_internet`: Adding the `internetClient` SID (`S-1-15-3-1`) to the token's capabilities.

### Q5: CLI Feasibility?
**Answer**: Feasible. `CreateAppContainerProfile` works for standard users. The main challenge is ensuring the workspace ACLs are correctly set and restored (or managed).

### Q6: Profile Lifecycle?
**Answer**:
- **Strategy**: To avoid profile residue, `agent-guard` will use a **deterministic, named profile** per user (e.g., `AgentGuard_Sandbox_Profile`).
- **Cleanup**: The profile will be created once and reused. If the user wants a full reset, a CLI flag (e.g., `--reset-sandbox`) can call `DeleteAppContainerProfile`.

---

## 3. 🚧 Risks & Mitigation
- **ACL Pollution**: Frequently updating ACLs on host folders can be slow or leave residue.
- **Mitigation**: Use a dedicated, isolated workspace root and ensure `agent-guard` cleanup logic is robust.
- **Complexity**: AppContainer is significantly more complex than Low-IL.
- **Mitigation**: Keep the implementation modular in `crates/agent-guard-sandbox/src/windows_appcontainer.rs`.
