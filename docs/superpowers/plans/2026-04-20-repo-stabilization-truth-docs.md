# Repository Stabilization And Truth-In-Docs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the biggest contributor traps and align active documentation with the current repository state without broadening runtime scope.

**Architecture:** Treat this as a stabilization batch, not a feature batch. First fix build and verification entrypoints, then update active docs and contributor guidance to match the merged short-term wedge, and finally remove one duplicated SDK/Core payload-parsing path.

**Tech Stack:** Rust workspace crates, PyO3/maturin, napi-rs/Node, Bash verification scripts, GitHub Actions.

---

### Task 1: Stabilize Build And Verification Entry Points

**Files:**
- Modify: `crates/agent-guard-python/Cargo.toml`
- Modify: `crates/agent-guard-python/pyproject.toml`
- Modify: `.gitignore`
- Modify: `.github/workflows/ci.yml`
- Create: `scripts/verify.sh`

### Task 2: Align Contributor And Product Docs With Current Reality

**Files:**
- Modify: `CLAUDE.md`
- Modify: `AGENTS.md`
- Modify: `README.md`
- Modify: `docs/README.md`
- Modify: `crates/agent-guard-python/README.md`
- Modify: `crates/agent-guard-node/README.md`

### Task 3: Remove Small Internal Inconsistencies

**Files:**
- Modify: `crates/agent-guard-sdk/src/guard.rs`
- Modify: `crates/agent-guard-sdk/tests/execute_integration.rs`
- Modify: `crates/agent-guard-sdk/tests/runtime_decision_integration.rs`

### Task 4: Add Repository Hygiene And Version-Consistency Checks

**Files:**
- Create: `scripts/check-version-consistency.sh`
- Modify: `scripts/verify.sh`
- Modify: `.github/workflows/ci.yml`
- Modify: `docs/README.md`

### Task 5: Verify, Commit, And Summarize Remaining Follow-Ups

**Files:**
- Reference: `docs/superpowers/specs/2026-04-20-repo-stabilization-truth-docs-design.md`
- Reference: `docs/superpowers/plans/2026-04-20-repo-stabilization-truth-docs.md`
