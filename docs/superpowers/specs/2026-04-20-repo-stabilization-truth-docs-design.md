# Repository Stabilization And Truth-In-Docs Design

## Goal

Fix the highest-friction contributor traps and align active documentation with the current codebase without expanding the execution surface or starting a larger architecture split.

## Scope

This batch covers four concrete areas:

1. Build and verification entrypoints
2. Active documentation accuracy
3. Small code consistency fixes
4. Repository hygiene guidance

## Decisions

### 1. Fix onboarding traps before expanding capability work

The highest priority is making the repository build and verify in a way that matches what the docs claim.

That means:

- `agent-guard-python` must stop enabling `extension-module` by default so `cargo build --workspace --all-features` is no longer the first command that fails for new contributors
- `Cargo.lock` must be tracked because this workspace contains executable and binding crates, not only reusable libraries
- the repo must expose one obvious verification entrypoint instead of asking contributors to infer the right command mix from CI

### 2. Prefer truthful documentation over deeper runtime refactors in this batch

The runtime wedge work on `main` already added owned execution for shell, file write, and outbound mutation HTTP. The remaining mismatch is not “the wedge does not exist”; it is that some active docs, examples, and contributor guidance still describe an older shell-first-only reality or gloss over runtime limitations.

This batch will update active docs to match the current codebase and will make limitations explicit:

- non-Bash validation depth is still shallower than Bash validation
- policy matching for HTTP is still primarily URL-centric, even though runtime execution now distinguishes mutation methods
- Python and Node bindings still choose the default sandbox internally and do not yet expose an explicit sandbox-selection API
- default sandbox fallback to `NoopSandbox` is visible in the SDK today and should be called out more clearly in binding docs

### 3. Keep control-plane code in the core SDK for now, but acknowledge it honestly

This repository already contains policy signing, execution receipts, metrics, anomaly detection, and SIEM export in the main SDK. This batch will not split those concerns into an `enterprise` crate because that would be a larger architectural change with compatibility and packaging consequences.

Instead, active docs will describe the current reality more honestly:

- the project is still a narrow adoption wedge around side-effect execution control
- the SDK also already includes governance-oriented features beyond that wedge

### 4. Make small consistency fixes where the behavior is already settled

This batch will make one surgical code consistency fix:

- stop duplicating Bash payload extraction logic in `agent-guard-sdk` and reuse the `agent-guard-core` extractor

This batch will not attempt to add a full validator layer for `read_file`, `write_file`, or `http_request`. That needs separate design work because it affects policy semantics, path normalization contracts, symlink handling, and backward compatibility.

## Non-Goals

This batch does not:

- introduce new side-effect capabilities
- split governance features into separate crates
- redesign the policy engine around HTTP methods
- implement full non-Bash validator parity
- expose new explicit sandbox-selection APIs in Python or Node

## Expected Outcome

After this batch:

- new contributors can follow documented build and verification commands without hitting the known Python-feature trap
- CI and local verification share one clear entrypoint
- active docs describe the current wedge and current limitations accurately
- the workspace shape and contributor guidance match the actual repository
- one duplicated payload parsing path is removed
