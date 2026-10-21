# Independent policy YAML parser migration

Date: 2026-10-21 (America/Los_Angeles). User explicitly authorized parser
selection, compatibility/negative tests and an independent review PR.
Baseline: main `a5140da0c1a8367d8879af48b3e51de8e83cfd06`.
Branch: `codex/yaml-parser-migration`; preserve the primary dirty checkout and
PR #175. No merge, release, tag, advisory update or automation is authorized.

## Selection and compatibility cost

RUSTSEC-2024-0449 has no patched `unsafe-libyaml` release. A rename to
`serde_yaml_ng` would preserve that chain. Select `serde-saphyr` 2.0.0 with
default features disabled and only `deserialize` enabled. Its typed Serde
integration and resource controls reduce the amount of custom parsing code.
`noyalib` 0.0.58 also requires Rust 1.89 and needs explicit duplicate/merge
configuration; `yaml-rust2` lacks Serde integration and would require a larger
adapter. Maintained/safe-Rust code is not proof of absence of vulnerabilities.

The supported build floor moves from declared Rust 1.79 to 1.89. Record the
change in user-facing notes and add an exact-toolchain core policy CI check;
do not imply an untested old compiler remains supported.

Primary references:

- [RustSec](https://rustsec.org/advisories/RUSTSEC-2024-0449.html).
- [serde-saphyr 2.0.0 manifest](https://github.com/bourumir-wyngs/serde-saphyr/blob/2.0.0/Cargo.toml).
- [Pinned parser options](https://github.com/bourumir-wyngs/serde-saphyr/blob/2.0.0/src/de/options.rs).
- [Pinned resource budgets](https://github.com/bourumir-wyngs/serde-saphyr/blob/2.0.0/src/de/budget.rs).
- [noyalib configuration](https://github.com/sebastienrousseau/noyalib/blob/v0.0.58/crates/noyalib/src/de/config.rs).

## Work sequence

- [x] Inspect the real policy surface and create a separate main-based tree.
- [x] Compare maintained parsers against the actual API and build floor.
- [x] Characterize old-parser semantics before changing production code:
  shipped presets, mixed rules, strict scalar selectors, duplicate keys,
  unknown fields, null/defaults, simple anchors, quoted Windows paths,
  raw-byte hashes and Ed25519 signatures, malformed reload retention.
- [x] Add finite negative tests and observe baseline failures for explicit
  input/alias/anchor/node/depth limits and unsupported tags. Do not execute
  command-shaped strings or resolve includes/properties.
- [ ] Replace both production YAML call sites; remove `serde_yaml` and
  `unsafe-libyaml` completely. Keep public errors and schema validations.
  Avoid type-driven scalar coercion broadening authorization.
- [ ] Enforce one document, strict YAML 1.2 boolean spellings, duplicate errors,
  no merges or unsupported tags, no include/property/robotics extensions,
  no source snippets, and bounded parsing/replay. Preserve ordinary finite
  aliases and original lexical `!!binary` string values (do not decode them).
- [ ] Bound string input and file reads at 1 MiB, structural depth at 64,
  aliases/anchors at 64 each, nodes/events at 16,384/32,768, replayed events
  at 8,192 and alias replay depth at 16. Keep raw input hashing/signing.
- [ ] Refresh only the known required `quinn-proto` security patch to 0.11.18
  (and its necessary closure), also present in #175. It is an independent
  existing audit blocker, not a reason to refresh all dependencies.
- [ ] Run targeted tests, full verification, strict all-target lint, fresh
  three-language parity, and actual audit/deny checks. Submit a separate PR
  and inspect its own exact-head cross-platform/MSRV CI conclusions.

## Acceptance and exclusions

Before production changes: compatibility tests 20/20 and SDK lifecycle tests
6/6 passed on the old parser. The finite resource/extension suite produced
2 passes / 7 failures (exit 101). An invalid deeply nested rule already failed
semantic validation; its new test distinguishes an earlier structural-budget
error, not a previously allowed authorization. The other failing controls
directly demonstrate acceptance beyond the proposed limits/unknown tags.

All existing valid shipped policies and decision/signature invariants must
pass; newly rejected extensions/oversized inputs must be documented. No
advisory ignores, last-wins duplicate handling, hidden security-test skips or
weaker reload behavior. Record red tests separately from production changes.
Public `PolicyError` categories stay; parser-specific wording can change.

This PR does not include #175's Attenu/seccomp changes, bump the release,
rewrite installed user policies, replace the broker deployment, or repair
Windows handle/general hard-link limitations. Final CI evidence belongs in
the PR rather than an endless self-head documentation/CI loop.
