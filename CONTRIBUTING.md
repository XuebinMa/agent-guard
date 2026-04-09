# Contributing to agent-guard

Thank you for your interest in contributing to `agent-guard`! As a security-focused project, we maintain high standards for code quality and reliability.

## Code of Conduct

Please be respectful and professional in all interactions.

## Development Process

1. **Fork the repository** and create your branch from `main`.
2. **Install dependencies**:
   - Rust 1.70+
   - Node.js 18+
   - Python 3.10+
3. **Run tests**:
   ```bash
   cargo test --workspace --all-features
   ```
4. **Follow Rust Standards**:
   - Every `unsafe` block must have a `// Safety:` comment explaining why it is safe.
   - Avoid `unwrap()` in library code; use `expect()` with context or `?`.
   - Run `cargo clippy` and `cargo fmt`.

## Security

Please report vulnerabilities following our [Security Policy](SECURITY.md).

## Pull Request Guidelines

- Describe the change and the problem it solves.
- Include new tests for any bug fixes or features.
- Ensure the CI pipeline passes.

Thank you for your contributions!
