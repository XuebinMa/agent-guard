# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
