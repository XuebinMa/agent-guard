# File Path Validator Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add normalized, symlink-aware path validation for `read_file` and `write_file` without changing the public policy schema or widening runtime scope.

**Architecture:** Introduce a shared path-resolution helper in `agent-guard-core`, route path-based policy matching through it, and extend focused SDK tests to cover traversal and symlink escape cases. Keep the implementation fail-closed and reuse existing decision codes where possible.

**Tech Stack:** Rust workspace, `agent-guard-core`, `agent-guard-sdk`, existing integration tests, `tempfile`

---

### Task 1: Add the first failing integration tests

**Files:**
- Modify: `crates/agent-guard-sdk/tests/integration.rs`

- [ ] **Step 1: Write the failing tests**

Add focused tests covering:

```rust
#[test]
fn read_file_relative_parent_escape_is_denied() { /* ../ escape */ }

#[test]
fn write_file_symlink_escape_is_denied() { /* symlink in workspace -> outside */ }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p agent-guard-sdk --test integration read_file_relative_parent_escape_is_denied write_file_symlink_escape_is_denied`
Expected: FAIL because the current path checks still operate on the raw payload path.

- [ ] **Step 3: Commit the red tests**

```bash
git add crates/agent-guard-sdk/tests/integration.rs
git commit -m "test: cover file path traversal and symlink escapes"
```

### Task 2: Add shared path normalization in core

**Files:**
- Create: `crates/agent-guard-core/src/file_paths.rs`
- Modify: `crates/agent-guard-core/src/lib.rs`
- Modify: `crates/agent-guard-core/src/policy.rs`

- [ ] **Step 1: Add a shared path-resolution helper**

Implement a helper that:

```rust
pub fn resolve_policy_path(path: &str, working_directory: Option<&Path>) -> Result<PathBuf, GuardDecision>
```

Behavior:
- resolve relative paths against `working_directory` when present
- lexically normalize components
- canonicalize an existing target
- for non-existent write targets, canonicalize the nearest existing parent and reattach the suffix

- [ ] **Step 2: Route path-based policy matching through the helper**

Update `PolicyEngine` path matching for `read_file` and `write_file` so it uses the resolved path string instead of the raw payload path string.

- [ ] **Step 3: Run the targeted tests**

Run: `cargo test -p agent-guard-sdk --test integration read_file_relative_parent_escape_is_denied write_file_symlink_escape_is_denied`
Expected: PASS

- [ ] **Step 4: Commit the core path normalization work**

```bash
git add crates/agent-guard-core/src/file_paths.rs crates/agent-guard-core/src/lib.rs crates/agent-guard-core/src/policy.rs
git commit -m "feat: normalize file tool paths before policy checks"
```

### Task 3: Cover happy-path regression cases

**Files:**
- Modify: `crates/agent-guard-sdk/tests/integration.rs`
- Modify: `crates/agent-guard-sdk/tests/execute_integration.rs`

- [ ] **Step 1: Add regression tests for safe nested paths**

Add tests showing that:

```rust
#[test]
fn write_file_nested_allowlist_path_still_allows() { /* safe path */ }

#[test]
fn execute_write_file_with_normalized_relative_path_still_succeeds() { /* ./nested/file.txt */ }
```

- [ ] **Step 2: Run the focused test files**

Run: `cargo test -p agent-guard-sdk --test integration`
Run: `cargo test -p agent-guard-sdk --test execute_integration`
Expected: PASS

- [ ] **Step 3: Commit the regression coverage**

```bash
git add crates/agent-guard-sdk/tests/integration.rs crates/agent-guard-sdk/tests/execute_integration.rs
git commit -m "test: cover normalized file path happy paths"
```

### Task 4: Final verification and docs touch-up

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the limitation note**

Tighten the README note so it no longer says file tools are mostly policy-centric after this change; keep the HTTP caveat explicit.

- [ ] **Step 2: Run verification**

Run: `cargo test -p agent-guard-core`
Run: `cargo test -p agent-guard-sdk`
Run: `./scripts/verify.sh rust`
Expected: PASS

- [ ] **Step 3: Commit the final polish**

```bash
git add README.md
git commit -m "docs: update file path validation scope note"
```
