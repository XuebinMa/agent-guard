# agent-guard v0.2.0 Release Candidate Demos

This directory contains standardized demonstrations of the core security features in `agent-guard` v0.2.0.

## Demo 1: Happy Path (Standard Execution)
**Purpose**: Shows the standard flow from tool call to execution with audit and provenance tracing.
- **Run**: `cargo run --example demo_happy_path`
- **Key Value**: Demonstrates the low-latency security wrapper and cryptographic receipts.

## Demo 2: Malicious Block (Deny Fuse)
**Purpose**: Shows how the system reacts to malicious behavior by automatically locking agents.
- **Run**: `cargo run --example demo_malicious_block`
- **Key Value**: Demonstrates proactive defense against probing or repetitive policy violations.

## Demo 3: Platform Transparency (UCM Parity)
**Purpose**: Shows how `agent-guard` abstracts system-level capabilities via the Unified Capability Model.
- **Run**: `cargo run --example demo_transparency`
- **Key Value**: Demonstrates the `CapabilityDoctor` utility and platform-agnostic security posture.

---
**Note**: All demos require the Rust toolchain and are run within the `agent-guard-sdk` context.
