# agent-guard Documentation Hub (v0.2.0-rc1)

`agent-guard` is an execution control layer for agent side effects. This hub is organized around the current developer path first: understand the shell-first proof point, get a real execution boundary in place, then go deeper into reference, operations, and longer-term roadmap material.

![agent-guard proof demo screenshot](assets/demo-proof-terminal.svg)

---

## 📣 Latest Activity

- **Latest Release** → [`v0.2.0-rc1`](https://github.com/XuebinMa/agent-guard/releases/tag/v0.2.0-rc1)
- **Community Thread** → [GitHub Discussions #1](https://github.com/XuebinMa/agent-guard/discussions/1)

If you are arriving from GitHub or social posts, these are the two best entry points before you dive deeper into the docs.

Current boundary note:

- the strongest current `enforce` path is shell / Bash execution
- non-shell tools primarily use `check` + policy gate unless your host adds its own runtime boundary
- use `cargo run -p guard-verify -- doctor --format text` to verify the real host boundary on the machine you actually deploy

---

## 🎯 Find by Goal (Objective)
- **I want the fastest proof this works** → [Three-Minute Proof](guides/getting-started/three-minute-proof.md)
- **I want to integrate quickly** → [User Manual](guides/getting-started/user-manual.md)
- **I want to secure shell tools first** → [Secure Shell Tools](guides/getting-started/secure-shell-tools.md)
- **I need to choose `check` vs `enforce`** → [Check vs Enforce](guides/getting-started/check-vs-enforce.md)
- **I want a fast attack demo** → [Attack Demo Playbook](guides/getting-started/attack-demo-playbook.md)
- **I want to connect ChatGPT Actions to agent-guard** → [ChatGPT Actions Integration](guides/getting-started/chatgpt-actions.md)
- **I want policy signing, receipts, and doctor reports after first integration** → [Trust Tooling](guides/getting-started/trust-tooling.md)
- **I want to deploy safely** → [Deployment Guide](guides/operations/deployment-guide.md)
- **I want to audit security posture** → [Threat Model](threat-model.md)
- **I want to know what frameworks are actually supported** → [Framework Support Matrix](framework-support-matrix.md)
- **I want to compare platform gaps** → [Capability Parity Matrix](capability-parity.md)
- **I want roadmap context, not first-run guidance** → [Architecture & Future Directions](architecture-and-vision.md)
- **I want material I can share publicly** → [Launch Kit](guides/adoption/launch-kit.md)
- **I want a release post or social draft** → [Release Announcement Template](guides/adoption/release-announcement.md)
- **I want ready-made replies for new users** → [FAQ For New Users](guides/adoption/faq-for-new-users.md)

---

## 🚀 Start Here (Getting Started)
For AI application and agent developers integrating `agent-guard` for the first time.

- ⏱️ **[Three-Minute Proof](guides/getting-started/three-minute-proof.md)**: The fastest path to seeing a risky tool call blocked.
- 🔐 **[Secure Shell Tools](guides/getting-started/secure-shell-tools.md)**: The best first use case and how to protect it.
- ⚖️ **[Check vs Enforce](guides/getting-started/check-vs-enforce.md)**: How to choose the right adapter mode.
- 📘 **[User Manual](guides/getting-started/user-manual.md)**: Installation, configuration, and basic integration after the proof path.

After the first run:

- 🎬 **[Attack Demo Playbook](guides/getting-started/attack-demo-playbook.md)**: A short, repeatable “before vs after” demo flow.
- 🤖 **[ChatGPT Actions Integration](guides/getting-started/chatgpt-actions.md)**: How to place agent-guard behind a Custom GPT Action.
- 🔏 **[Trust Tooling](guides/getting-started/trust-tooling.md)**: Policy signing, receipt verification, and doctor reports once you need deeper audit and verification workflows.
- 🚀 **[Migration Guide](guides/getting-started/migration-guide.md)**: Moving from No-op to Hardened execution.

---

## 🧭 Framework Readiness

For developers deciding which binding or adapter path to use today.

- 🧭 **[Framework Support Matrix](framework-support-matrix.md)**: Current support status across Rust, Node, Python, LangChain-style adapters, OpenAI-style adapters, and ChatGPT Actions patterns.

---

## 📣 DevRel & Adoption

For maintainers and early adopters who want to explain or share the project clearly.

- 📣 **[Launch Kit](guides/adoption/launch-kit.md)**: Positioning, short demo scripts, social post templates, and sharing guidance.
- 🧪 **[Case Study: Protecting a Shell-Enabled Agent](guides/adoption/case-study-shell-agent.md)**: A concrete narrative for the strongest current use case.
- 🖼️ **[Demo Asset Workflow](guides/adoption/demo-asset-workflow.md)**: Maintainer workflow for keeping screenshots and short demo clips consistent with the live proof demo.
- 📢 **[Release Announcement Template](guides/adoption/release-announcement.md)**: A ready-to-adapt GitHub release or project update structure.
- 🗣️ **[GitHub Discussions Announcement](guides/adoption/discussions-announcement.md)**: A finished announcement draft ready to post in Discussions.
- 🌐 **[External Channel Post Pack](guides/adoption/external-channel-post-pack.md)**: First-wave post drafts for X, Reddit, LinkedIn, Hacker News, and Chinese dev communities.
- 💬 **[Social Post Templates](guides/adoption/social-posts.md)**: Short, medium, and long post drafts for community channels.
- ❓ **[FAQ For New Users](guides/adoption/faq-for-new-users.md)**: Reusable answers to common first-contact questions.

---

## ⚙️ Operators & Deployers (Operations)
For SREs and DevOps engineers managing `agent-guard` in production environments.

- 🚀 **[Deployment Guide](guides/operations/deployment-guide.md)**: Production architecture and hardening.
- 📊 **[Observability & Monitoring](guides/operations/observability.md)**: Metrics, Audit logs, and SIEM integration.

---

## 🔒 Security & Audit
For security researchers and auditors reviewing the system's defensive posture.

- 🏹 **[Threat Model](threat-model.md)**: Formal asset analysis and attack surface matrix.
- 🗺️ **[Capability Parity Matrix](capability-parity.md)**: Feature alignment across Linux, macOS, and Windows.
- 🔍 **[Security Audit Report](security-audit.md)**: Latest pre-release self-audit findings.

---

## 🏗️ Architecture & Future Directions
For maintainers who want longer-term context rather than first-run integration guidance.

- 🏗️ **[Architecture & Future Directions](architecture-and-vision.md)**: Current execution-control architecture notes plus longer-term expansion context.

---

## 📂 Project History
- 🏛️ **[Document Archive](archive/README.md)**: Historical design documents and milestone records.
