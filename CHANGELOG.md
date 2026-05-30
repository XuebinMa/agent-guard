# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`cargo-release` automation rewrites the `[Unreleased]` heading at each release; do not delete it.

## [Unreleased]

### Added
- **Claude Code plugin (preview)**: agent-guard now installs as a Claude Code plugin. The repo doubles as a single-plugin marketplace (`.claude-plugin/marketplace.json` + `plugin.json`); `/plugin marketplace add XuebinMa/agent-guard` then `/plugin install agent-guard@agent-guard` registers a `PreToolUse` hook over `Bash`/`Write`/`Edit`/`WebFetch` that enforces the bundled outbound preset via `guard-hook`. The hook wrapper (`scripts/guard-hook-plugin.sh`) is fail-open (a missing binary or policy emits `allow`), honours `AGENT_GUARD_HOOK=off`, and keeps stdout reserved for the decision by routing audit records to stderr (or to a file with `audit: { output: file }`). See `docs/guides/operations/claude-code-plugin.md`.
- **Content layer (experimental, opt-in)**: credential / PII detection on outbound content (`write_file` content and `http_request` body) behind the off-by-default `content` feature. Add a `content:` block to any tool rule with `mode: block | mask | warn` and an optional `detect: [secrets, pii]` list. `block` denies (`SENSITIVE_CONTENT_BLOCKED`), `mask` rewrites findings to `[REDACTED:<label>]` before execution, `warn` executes unchanged; `mask`/`warn` emit a `ContentFinding` audit record carrying labels and counts only (never raw content). Run `cargo run -p agent-guard-sdk --example content_policy --features content`. See README § Content layer.
- `cargo-release` integration. New `release.toml` configures workspace-coordinated releases (shared version across all seven crates, single tag per workspace, manual push). See `CONTRIBUTING.md` § Releasing for the workflow.

## [0.2.0-rc1] - 2026-04-08

### Added
- **Windows Sandboxing**: Support for Low Integrity Level (Low-IL) and Job Objects.
- **AppContainer**: Experimental prototype for SID-based isolation (Opt-in).
- **macOS Seatbelt**: Formal integration with `sandbox-exec`.
- **Unified Capability Model (UCM)**: Decoupled security policy from platform implementation.
- **Provenance Receipts**: Ed25519-signed execution receipts for audit verification.
- **SIEM Integration**: Real-time audit log export via Webhooks.
- **Adoption Suite**: Capability Doctor and Migration Guides.

### Fixed
- CWE-78: Command injection vulnerabilities across all platforms via shlex-style escaping.
- CWE-22: Path traversal validator improvements.
- Fixed multiple memory safety and handle leak issues in Win32 implementation.
- Standardized API naming and result schemas.

## [0.1.0] - 2026-03-01
- Initial Alpha release with core SDK.
