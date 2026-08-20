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

- `src/bash/ast.rs` — the shell syntax front-end (tree-sitter-bash). Parses the
  command and recovers every command position from the syntax tree, so a
  command nested in `{ …; }`, `( … )`, `if`, `while`, `for`, `case`, or a
  function body is still classified. **Fail-closed on syntax:** an unparseable
  input, or a node kind outside `STRUCTURAL_KINDS`, yields `TooComplex`, which
  restricted modes deny. Teaching the walker a new kind is a deliberate
  security decision — `grammar_kinds_are_all_classified` fails the build if a
  grammar upgrade introduces one you have not classified.
- `src/bash/tokenize.rs` — quote-aware token splitting (`shell_split`) plus the
  per-command scanners (code laundering, inline-code interpreters, dynamic
  command words, …). The scanners iterate the command positions `ast.rs`
  recovers; they no longer do their own flat segmentation.
- `src/bash/tables.rs` — the allow / read-only / destructive command tables.
- `src/bash/wrappers.rs` — transparent wrappers (`sudo`, `env`, `xargs`,
  `timeout`, `nice`, …) that must be unwrapped to reach the real command.
- `src/bash/destructive.rs`, `src/bash/read_only.rs` — intent classification.
- `src/bash/paths.rs` — extracts the write/read targets a command touches.
- `src/path.rs` — path normalisation + workspace-escape / traversal checks.
- `src/content/` — secret/PII/redaction. **Feature-gated, off by default.**

## Where bypasses hide (the things to get right)

1. **Chaining, separators, and nesting.** A deny must not be escapable by `|`,
   `;`, `&&`, `||`, command substitution, a newline, or by nesting the command
   inside a grouping construct. Command positions come from the grammar
   (`ast.rs`), so classify from `ResolvedCommand::argv` — never re-derive a
   command word by splitting a string, which is what made this a recurring bug
   class across fifteen fixes. The historical corpus is
   `tests/fixtures/shell_bypass_corpus.json`; run it before and after any
   change here.
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

## The `content` feature is opt-in, spike-grade

`src/content/` (secret/PII detection, redaction) is behind the off-by-default
`content` feature. A default build carries no content scanning; the SDK's
`content` feature wires these detectors into the Guard pipeline — `write_file`
content and `http_request` body on the outbound path, plus input text via
`Guard::check_content`. The detector set is spike-grade (named patterns +
entropy, regex + Luhn) — do not describe it as a DLP engine.

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
