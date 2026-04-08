# Phase 2 Done Definition Checklist — agent-guard

This document defines the completion of Phase 2 (Python & Sandbox Implementation).

## Core SDK (Rust)
- [x] `Guard::execute()` implemented in `agent-guard-sdk`.
- [x] Integration tests for `execute()` passing with `NoopSandbox`.
- [x] `Tool::Bash` payload contract fixed to structured JSON `{"command": "..."}`.
- [x] Bash validator updated with shell separator awareness (`|`, `;`, `&&`, `||`).
- [x] All 169+ Rust tests in the workspace are passing.

## Python Binding
- [x] `agent-guard-python` crate implemented via PyO3 0.28.
- [x] Python `Guard.check()` supports full context and structured payload.
- [x] Pytest suite (20+ tests) passing.
- [x] `maturin develop` build system verified.

## Ecosystem Integration (Demos)
- [x] `demos/python/generic_demo.py`: 10+ framework-agnostic scenarios.
- [x] `demos/python/langchain_demo.py`: `GuardedBashTool` implementation.
- [x] Both demos run successfully with `policy.example.yaml`.

## Linux Sandbox (Seccomp)
- [x] `SeccompSandbox` implementation in `agent-guard-sandbox/src/linux.rs`.
- [x] `ReadOnly` and `WorkspaceWrite` syscall allowlists defined and implemented.
- [x] `KilledByFilter` error detection for `SIGSYS`.
- [x] `libseccomp` feature flag and C dependency wired.

## Documentation (Public State)
- [x] `README.md` updated with Phase 2 status, workspace structure, and new API.
- [x] `docs/phase2-design.md` updated to implementation summary.
- [x] `docs/sandbox-linux.md` created with usage requirements and security details.
- [x] All outward-facing documentation is synchronized with current implementation.
