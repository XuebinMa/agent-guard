# agent-guard

> **The Ultimate Security Layer for AI Agents.**  
> **Intercept tool calls, evaluate against zero-trust policies, and execute in hardened OS sandboxes.**

[![Version](https://img.shields.io/badge/Version-0.2.0--rc1-blue.svg)]()
[![Phase](https://img.shields.io/badge/Phase-7%20Complete-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)]()

AI Agents are powerful, but giving them raw shell access or uncontrolled API keys is a recipe for disaster. `agent-guard` provides a high-performance, multi-layered security wrapper that ensures your LLM never escapes its boundaries.

---

## ✨ Why agent-guard?

Unlike basic "System Prompt" instructions, `agent-guard` enforces security at the **OS level**. Even if your Agent is fully subverted via Prompt Injection, the host system remains protected.

### 🚀 Key Advantages
- 🛡️ **Defense in Depth**: Combines a YAML rule engine with multi-platform sandboxing (Linux Prototype, Windows, macOS).
- 📜 **Verifiable Provenance**: Ed25519 Signed Receipts (Automatic) for cryptographic execution proof.
- 🔒 **Proactive Protection**: Built-in **Deny Fuse** automatically locks out Agents after repeated policy violations to stop active probing.
- 📊 **Enterprise Observability**: Real-time Prometheus metrics and SIEM-ready Webhooks for instant incident response.
- 🏥 **Security Transparency**: Built-in `CapabilityDoctor` to verify exactly what your host OS supports—no more black-box security.

---

## 📈 Performance & Reliability (Stress Tested)

`agent-guard` is built for high-scale production environments. Our v0.2.0-rc1 release has been [rigorously tested](docs/security-audit.md#2-findings--remediations):
- **Zero Resource Leaks**: Passed 60,000+ executions in 30s with zero handle or memory drift.
- **Concurrent Correctness**: Successfully handled 128+ concurrent agents with 100% decision accuracy.
- **Fail-Closed Design**: Guaranteed block on any sandbox or environment initialization failure.

---

## 📺 See it in Action

Run our standardized demos to see the security layers in real-time:

- **Happy Path**: `cargo run --example demo_happy_path` (Standard execution + cryptographic receipts)
- **Malicious Block**: `cargo run --example demo_malicious_block` (See the Deny Fuse lock out an attacker)
- **The Comparison**: `cargo run --example demo_comparison` (No Guard vs. Full Guard side-by-side)
- **Host Transparency**: `cargo run --example demo_transparency` (What can your host OS defend against?)

---

## 📖 Documentation & Usage

Ready to secure your agents? Follow our comprehensive guides:

- 📘 **[User Manual](docs/guides/getting-started/user-manual.md)** - **Start here!** Installation, configuration, and integration guide.
- 🏗️ **[Architecture & Vision](docs/architecture-and-vision.md)** - Understanding the four layers of defense.
- 🗺️ **[Capability Matrix](docs/capability-parity.md)** - Feature alignment across Linux, macOS, and Windows.
- 🚀 **[Documentation Hub](docs/README.md)** - Full index of operational and security guides.

---

## 🗺️ Roadmap

- [x] **Phase 1-4**: Core Engine, Linux Sandbox, Telemetry, Anomaly Detection.
- [x] **Phase 5-6**: Windows Low-IL, Unified Capability Model (UCM), Signed Receipts (Automatic), SIEM.
- [x] **Phase 7**: Production Hardening, Cross-platform Parity, AppContainer Prototype.
- [x] **Phase 8**: RC Validation & Stress Testing.
- [ ] **Phase 9 (Current)**: v0.3.0 Ecosystem & Trust: LangChain/OpenAI Adapters, Receipt Verification CLI.
- [ ] **Phase 10 (Future)**: TPM-backed Remote Attestation, Linux Landlock Integration.

---

## 🤝 Contributing

We welcome security research and contributions. Please see `CONTRIBUTING.md` for details.

*Copyright © 2026 agent-guard team. Distributed under the MIT License.*
