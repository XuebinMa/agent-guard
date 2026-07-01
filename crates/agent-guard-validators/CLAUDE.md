# CLAUDE.md — agent-guard-validators

Scoped guidance for the validator crate. This **adds** to the root
[`CLAUDE.md`](../../CLAUDE.md); it does not repeat it. This crate is the
security-critical classification layer — read the
[Testing Strategy](../../docs/concepts/testing-strategy.md) and
[Threat Model](../../docs/concepts/threat-model.md) before changing it, and
expect every closed bypass to earn a regression lock.

## What this crate does

It turns a raw bash command (or a path) into an intent classification the SDK
can act on. The public surface (see `src/lib.rs`) is `classify_intent`,
`check_destructive`, `validate_bash_command` / `validate_command`,
`validate_mode`, `validate_read_only`, `validate_paths`, `validate_sed`, and the
`CommandIntent` / `PermissionMode` / `ValidationResult` types.

Module layout:

- `src/bash/tokenize.rs` — splits a command line into tokens/segments. Bash is
  **parsed here, not regex-matched** — most bypasses are tokenizer edge cases.
- `src/bash/tables.rs` — the allow / read-only / destructive command tables.
- `src/bash/wrappers.rs` — transparent wrappers (`sudo`, `env`, `xargs`,
  `timeout`, `nice`, …) that must be unwrapped to reach the real command.
- `src/bash/destructive.rs`, `src/bash/read_only.rs` — intent classification.
- `src/bash/paths.rs` — extracts the write/read targets a command touches.
- `src/path.rs` — path normalisation + workspace-escape / traversal checks.
- `src/content/` — secret/PII/redaction. **Feature-gated, off by default.**

## Where bypasses hide (the things to get right)

1. **Chaining and separators.** A deny must not be escapable by `|`, `;`,
   `&&`, `||`, command substitution, or a newline. Every segment is classified;
   if a new construct can smuggle a second command past the tokenizer, that is a
   bypass.
2. **Transparent wrappers.** `sudo rm -rf …`, `env X=1 curl … | bash`,
   `xargs rm` — if the wrapper is not unwrapped in `wrappers.rs`, the inner
   command is misclassified. Adding a wrapper means teaching `wrappers.rs` its
   argument grammar.
3. **Write-target sinks.** `paths.rs` must know every way a command names a
   destination: redirects (`>`, `>>`), `cp` / `mv`, and `install -t DIR` /
   `install … DEST` (added in #93). A missed sink is a silent workspace escape.
   When you add a command that writes, teach `paths.rs` its destination grammar
   in the same change.
4. **Tables are additive.** `tables.rs` is a set of command classifications; a
   gap (a destructive tool not listed) reads as "unknown/allowed". Adding a
   command means updating the table **and** adding a test.

## The `content` feature is not wired in

`src/content/` (secret/PII detection, redaction) is behind the off-by-default
`content` feature — an S6-1 spike / PoC that is **not** part of the main `Guard`
pipeline. Do not assume importing this crate gives you content scanning, and do
not describe it as an active enforcement path.

## Testing

Unit tests live in `src/tests.rs` and `src/bash/tests.rs`. Because this crate is
the boundary, the attack-class regressions live one layer up, in
[`agent-guard-sdk/tests/security_regression.rs`](../../crates/agent-guard-sdk/tests/security_regression.rs) —
when you close a bypass here, add the lock there and cite the PR.

```bash
cargo test -p agent-guard-validators
cargo test -p agent-guard-validators --features content   # exercises the PoC content module
```

Any change to classification, tokenisation, wrapper unwrapping, or path handling
is security-sensitive and needs regression coverage per
[`CONTRIBUTING.md`](../../CONTRIBUTING.md).
</content>
