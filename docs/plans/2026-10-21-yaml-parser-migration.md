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
- [x] Replace both production YAML call sites; remove `serde_yaml` and
  `unsafe-libyaml` completely. Keep public errors and schema validations.
  Avoid type-driven scalar coercion broadening authorization.
- [x] Enforce one document, only the true/false boolean family, duplicate errors,
  no merges or unsupported tags, no include/property/robotics extensions,
  no source snippets, and bounded parsing/replay. Preserve ordinary finite
  aliases and original lexical `!!binary` string values (do not decode them).
- [x] Bound string input and file reads at 1 MiB, structural depth at 64,
  aliases/anchors at 64 each, nodes/events at 16,384/32,768, replayed events
  at 8,192 and alias replay depth at 16. Keep raw input hashing/signing.
- [x] Apply the known required `quinn-proto` security patch to 0.11.18
  (and its necessary closure), also present in #175. It is an independent
  existing audit blocker, not a reason to refresh all dependencies.
- [x] Run targeted tests, full verification, strict all-target lint and fresh
  three-language parity on the completed local tree.
- [ ] Submit a separate PR and inspect its own exact-head audit/deny,
  cross-platform and MSRV CI conclusions. Record these in the PR body so
  recording the final head does not create another commit/CI cycle.

## Acceptance and exclusions

Before production changes: compatibility tests 20/20 and SDK lifecycle tests
6/6 passed on the old parser. The finite resource/extension suite produced
2 passes / 7 failures (exit 101). An invalid deeply nested rule already failed
semantic validation; its new test distinguishes an earlier structural-budget
error, not a previously allowed authorization. The other failing controls
directly demonstrate acceptance beyond the proposed limits/unknown tags.

The candidate parser initially exposed a distinct-key collision when generic
values collected different YAML keys into the same string key. A separate
failing regression preceded the recursive collector fix; both YAML-node and
final-string duplicates are now rejected before a value can be overwritten.
This was caught during migration, not a new claim about a released exploit.

Compatibility is characterized, not universal YAML equivalence: all ASCII case
variants of true/false are now booleans (the old parser supported six spellings).
Typed string fields reject unquoted numbers/booleans rather than accepting
implicit string coercion. The [user-facing profile](../concepts/policy-yaml.md)
records these changes and the finite limits. Quotes are the remedy for literal
string data; editing a signed file requires signing the new original bytes.

All existing valid shipped policies and decision/signature invariants must
pass; newly rejected extensions/oversized inputs must be documented. No
advisory ignores, last-wins duplicate handling, hidden security-test skips or
weaker reload behavior. Record red tests separately from production changes.
Public `PolicyError` categories stay; parser-specific wording can change.

## Local verification checkpoint before CI dependency follow-up

Final `./scripts/verify.sh full` exited 0 on macOS with Homebrew Rust/Cargo
1.94.1. Rust summaries: 1,188 passed, zero failed, three existing ignored
entries (opt-in copy-cost probe, isolated-child-only proxy probe and an
audit performance smoke); Python 108 passed / one optional framework skip;
Node adapter/framework/native/type checks and 14 plugin tests passed.
The 43 migration tests are 20 compatibility + 12 limits + 4 scalar typing +
7 SDK lifecycle tests, with no skips. Strict all-target clippy, rustfmt,
52 script tests, 83-document checks and version/action-pin checks passed.
Freshly built Rust/Python/Node bindings matched in all 70 parity scenarios.

The Node dev-tool tree still emits six audit warnings; `npm audit --omit=dev`
for the binding reports zero. The dependency-free plugin has no lockfile, so
`npm audit` cannot independently assess it (`ENOLOCK`); no lockfile or dev
dependency refresh was fabricated for this migration. Linux/seccomp, Windows,
native-container and Rust 1.89 execution are CI gates, not local macOS claims.
Neither local green checks nor a previous PR substitutes for the new head's
actual cargo-audit/cargo-deny conclusions.

## First exact-head CI and minimal TLS follow-up

PR #176 head `0328c17d59c2007bf44500e6d68c40af481eff93`, run
`39644217696`, passed the actual Rust 1.89.0 job but failed cargo-deny on six
pre-existing TLS advisories, not YAML: RUSTSEC-2026-0346/0347/0348/0349
(`rustls`), RUSTSEC-2026-0382 (`rustls-webpki`) and RUSTSEC-2026-0383
(`webpki-root-certs`). The last two were issued 2026-10-20. The failing job
was `119375420229`; its bans, licenses and sources checks were successful.

Apply exactly `rustls` 0.23.46, `rustls-webpki` 0.103.16 and
`webpki-root-certs` 1.0.10. The follow-up lock diff changes only these three
versions/checksums; no broad update, new feature or ignore rule. Upstream
[rustls advisory](https://rustsec.org/advisories/RUSTSEC-2026-0346.html),
[verification advisory](https://rustsec.org/advisories/RUSTSEC-2026-0382.html)
and [root-store advisory](https://rustsec.org/advisories/RUSTSEC-2026-0383.html)
confirm these patched ranges. The new head requires a fresh full/lint/parity
and its own CI; the first run's partial green results do not transfer. Final
results will be recorded in the PR body without another self-head commit.

This PR does not include #175's Attenu/seccomp changes, bump the release,
rewrite installed user policies, replace the broker deployment, or repair
Windows handle/general hard-link limitations. Final CI evidence belongs in
the PR rather than an endless self-head documentation/CI loop.
