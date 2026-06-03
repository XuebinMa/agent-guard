## Summary

<!-- What does this change do, and why? Link the related issue, e.g. Closes #123 -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / cleanup
- [ ] Docs
- [ ] CI / tooling

## Checklist

- [ ] `./scripts/verify.sh full` passes locally (or `rust` / `lint` for scoped changes)
- [ ] Tests added or updated for the behavior change
- [ ] Security-sensitive changes (validators, sandbox, policy, signing) include regression coverage in `crates/agent-guard-sdk/tests/security_regression.rs` where applicable
- [ ] Cross-language parity preserved if a public type or decision surface changed (Rust / Python / Node)
- [ ] Commits follow Conventional Commits (`feat:`, `fix:`, `docs:`, …)
- [ ] Docs updated if behavior, policy syntax, or public API changed
- [ ] No secrets, tokens, or internal-only material added

## Test plan

<!-- How did you verify this? Commands run and cases covered. -->
