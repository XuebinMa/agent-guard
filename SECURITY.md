# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x:                |

## Reporting a Vulnerability

We take the security of `agent-guard` seriously. If you believe you have found a security vulnerability, please report it to us by emailing [verimind.contact@gmail.com](mailto:verimind.contact@gmail.com).

Please do not report security vulnerabilities via public GitHub issues.

### What to include

A useful report contains:

- The affected version (or commit SHA) and platform.
- A short description of the impact (what an attacker can do).
- A reproduction recipe — minimal policy YAML, payload, and expected vs actual behavior. Attaching a failing test case under `tests/security_regression.rs` accelerates triage substantially.
- Whether the issue requires a malicious policy, a malicious payload, or a malicious dependency to reach.

### Coordinated disclosure timeline

| Day | Step |
| :-- | :-- |
| 0 | You email the report. |
| ≤ 2 | We acknowledge receipt and assign an internal tracker. |
| ≤ 7 | We confirm the vulnerability or explain why we don't consider it one. For confirmed issues we propose a disclosure date. |
| ≤ 14 | A fix is in review or we coordinate an extended embargo with the reporter. |
| Disclosure | We publish a fixed release, a [GitHub Security Advisory](https://github.com/XuebinMa/agent-guard/security/advisories), and credit the reporter (unless they prefer anonymity). |

Critical vulnerabilities (RCE, sandbox escape, policy bypass) target a 7-day fix window. Lower-severity issues may take longer; we'll communicate the expected timeline in the acknowledgement.

We are happy to coordinate with downstream packagers and dependency maintainers when an issue affects them.

## Supply chain assurance

- The repository tracks two automated supply-chain checks in CI:
  - **`cargo-deny`** — license / advisory / source / ban policy (see [`deny.toml`](deny.toml)).
  - **`cargo-audit`** — daily-fresh RustSec advisory database scan.
- An [SBOM](https://en.wikipedia.org/wiki/Software_Bill_of_Materials) (CycloneDX format) is produced for every push to `main` and downloadable from the `sbom` CI job artifact.
- Known transitive advisories under `ignore` in `deny.toml` are documented inline with the upstream they reach through and the migration that removes them. The ignore list is reviewed each release; entries should not outlive their reason.

## Out of scope

- Deliberately misconfigured policies. `agent-guard`'s job is to enforce the policy you give it. A policy that allows `rm -rf /` will allow `rm -rf /`.
- Vulnerabilities in user code wrapped by the adapters but outside the agent-guard call path.
- Issues in dependencies that have already shipped a fix and are blocked only by `deny.toml`'s ignore list — those are tracked in the advisory comments, not as new vulnerabilities.

Thank you for helping keep `agent-guard` safe.
