# Policy YAML profile and parser migration

Status: unreleased source change, reviewed on 2026-10-21. The published 0.2.8
packages do not contain this migration. No release or advisory is changed here.

## Selection

The former `serde_yaml` 0.9.34 dependency uses `unsafe-libyaml` 0.2.11, which has
[no patched release for its unmaintained advisory](https://rustsec.org/advisories/RUSTSEC-2024-0449.html).
This is a maintenance/dependency risk, not evidence by itself of a remotely
exploitable policy-parser bug. Renaming the dependency to `serde_yaml_ng` would
retain the same chain.

Use `serde-saphyr` 2.0.0 with default features off and only `deserialize` enabled.
It supplies Serde integration and finite parser/replay controls. The
[2.0.0 manifest](https://github.com/bourumir-wyngs/serde-saphyr/blob/2.0.0/Cargo.toml),
[options](https://github.com/bourumir-wyngs/serde-saphyr/blob/2.0.0/src/de/options.rs)
and [budgets](https://github.com/bourumir-wyngs/serde-saphyr/blob/2.0.0/src/de/budget.rs)
were checked against the implementation. This choice raises the source-build
floor to Rust 1.89; an exact 1.89.0 CI job tests the policy core. The full
workspace and OS/binding matrix still run on current stable Rust. This is not a
claim that every platform/binding was tested locally on the minimum compiler.

Other candidates were checked: `noyalib` 0.0.58 also requires 1.89 and needs
explicit duplicate/merge configuration; `yaml-rust2` would require a larger
custom Serde adapter. The comparison and original red/green sequence are in the
[migration plan](../plans/2026-10-21-yaml-parser-migration.md). Maintained code,
safe Rust and green tests are not proof of absence of parser vulnerabilities.

## Supported policy data

All PolicyEngine and Guard YAML construction/reload paths share one profile.
No general-purpose include, property substitution, binary decoding or robotics
extensions are enabled. This is a policy-data format, not arbitrary YAML.

- Exactly one document. Empty/second documents, unknown schema fields,
  duplicate keys and invalid rule shapes are rejected, not ignored.
- Duplicate protection applies both to YAML-node identity and to the final
  string key used by the schema. Distinct YAML keys cannot silently overwrite
  one custom-tool id or nested selector after conversion.
- Quoted strings keep their content. Rule selectors never coerce a number or
  boolean into a string. Standard `!!str` is supported; `!!binary` retains its
  lexical string, as before, rather than decoding base64 into another rule.
- Boolean fields accept any ASCII case of `true` and `false`, including mixed
  `tRuE`/`fAlSe` newly accepted by this parser. `yes`/`no`/`on`/`off`, numbers,
  and quoted booleans cannot enable/disable a boolean configuration field.
- String fields no longer accept implicit numeric/boolean-to-string coercion.
  For literal string data, use `audit: {output: file, file_path: '42'}`, not
  `file_path: 42`. The same quoting remedy applies to a literal `'true'` path.
- Finite anchors/aliases remain supported. Merge keys, recursive aliases,
  unsupported application tags and non-finite numbers are rejected.

The seven shipped policy files load unchanged. Existing absent-vs-empty audit
defaults, deny/ask/allow precedence, conditions, custom tools and optional-null
fields remain governed by the same policy schema. Public error categories are
retained; exact parser wording and source locations can change. Error snippets
are disabled, but an error may still quote the offending field/value: errors
are not a secret-redaction interface.

## Finite limits

These fixed limits fail at load/reload; they do not truncate or discard rules.
They bound parsing work, not wall-clock I/O time or arbitrary filesystem access.

| Resource | Maximum |
| --- | --- |
| Original UTF-8 source | 1,048,576 bytes (1 MiB), including comments |
| Documents / structural depth / flow nesting | 1 / 64 / 64 |
| Nodes / events | 16,384 / 32,768 |
| Anchors / aliases | 64 each |
| Recorded anchor events / bytes | 8,192 / 262,144 |
| Total replayed events / replay stack depth | 8,192 / 16 |
| Expansions of one anchor | 64 |
| Total scalar bytes | 1,048,576 |
| Merge keys / inclusion depth | 0 / 0 |

The file reader consumes at most the source limit plus one overflow-detection
byte, rather than reading the whole file and checking afterward. The same
reader is used before detached-signature file loading. It is not a regular-file
or read-timeout guarantee. For a rejected oversized/complex policy, simplify
or split deployment configuration; rules are never automatically removed to
make it fit.

Policy identity and detached Ed25519 verification use the exact original UTF-8
bytes, including comments, BOM and line endings, not a normalized/re-emitted
document. A failed parse/reload keeps the previous loaded snapshot. An edited
signed policy must be signed again; a valid signature does not make malformed
or over-budget YAML valid.

## Executable evidence

- [Compatibility](../../crates/agent-guard-core/tests/yaml_policy_compat.rs):
  20 baseline tests first passed on the old parser, including all shipped
  policies, decisions, original-byte hashes and quoted Windows paths.
- [Resource and extension limits](../../crates/agent-guard-core/tests/yaml_policy_limits.rs):
  original bounded negative suite first had seven failing tests; final tests
  cover byte boundaries, tags, anchors, aliases, replay work, structural/node
  budgets, merges, recursion and post-conversion key collisions.
- [Scalar typing](../../crates/agent-guard-core/tests/yaml_policy_types.rs):
  required quotes, literal strings and the explicit boolean spelling contract.
- [SDK lifecycle](../../crates/agent-guard-sdk/tests/yaml_policy_lifecycle.rs):
  constructors, signed raw-byte identity, bounded signed file reads and
  retention of the old verified snapshot after a failed reload.

These are safe unit/integration inputs: command-shaped strings are passed only
to decision functions, not executed. Cross-language parity must use freshly
built Python/Node bindings. Exact-head CI, audit/deny and per-OS conclusions
belong in the migration PR; old PR green checks are not evidence for this tree.
