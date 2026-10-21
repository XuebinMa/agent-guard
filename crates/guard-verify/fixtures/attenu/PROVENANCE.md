# Third-party interoperability corpus

`bundle_vectors_v1.json` is vendored verbatim from
[`attenu-io/attenu-guard`](https://github.com/attenu-io/attenu-guard),
`tests/vectors/bundles/bundle_vectors_v1.json`, which is licensed
Apache-2.0. It is unmodified.

- revision: `bundle_vectors_v1.5`, twenty-nine cases
- immutable source: [`96a3edbbfa93115004673a0724284c4ba5ddc500`](https://github.com/attenu-io/attenu-guard/blob/96a3edbbfa93115004673a0724284c4ba5ddc500/tests/vectors/bundles/bundle_vectors_v1.json)
- size: 242,534 bytes
- sha256: `1663000a67f38fcd54ff4856b39583b17ffec342f13f8d0921e2de0bc2bc25c5`

The first twenty cases are unchanged from v1.4 (175,552 bytes, sha256
`58d3546d67b1bafd8c96e0a01ae80b4b722f46af3459f19ee2b0ef34893da00d`).
The nine appended cases exercise v1 chains, entry-field/event restrictions and
non-object entries. Expectations match exact `reason`, `seq` and `node` values;
the verifier's optional `entry_index` remains a local diagnostic, not a
member of this published scoring triple.

Rows 19 and 20 pin the `policy` field: an allow may carry it, the only value
v1 defines is `unlisted`, and an undefined value buys no containment
exemption. This verifier scored **17 of 20** against them before the field
existed here.

It supersedes the 69,573-byte `v0.11.0` revision this directory carried
first (sha256 `90d7fa70…`), which had eight cases and no delegation
containment rows. The nine added cases are what first exercised the
containment path here.

It is vendored rather than fetched so the conformance test is hermetic and
so the bytes under test cannot drift. `attenu_corpus_fixture_bytes_are_pinned`
in `src/attenu/tests.rs` fails if this file changes.

## `envelope_vectors_v1.json`

Vendored verbatim from the same repository,
`tests/vectors/envelopes/envelope_vectors_v1.json`, unmodified.

- revision: `envelope_vectors_v1.2`, nineteen cases
- size: 197,346 bytes
- sha256: `a8be5ff764a86122ca09e94340416b7169531bf5d0cc76a0b1fc87f8272eb16e`

Row 19, `reject_duplicate_subject_defective_second`, exists because this
verifier's author reported that row 17 could not separate claim-first from
judge-first ordering. Rows 1 to 18 are unchanged from `v1.1`.

The hash is the one attenu-guard published and a second independent runner
reported for the same file, so byte identity was established before scoring
rather than assumed from a download. `attenu_envelope_fixture_bytes_are_pinned`
fails if this copy changes.

This corpus is the one that was **posted as text before anyone implemented
it**, which is why the run against it reads differently from the bundle one:
the reason vocabulary was published rather than inferred.

Our verifier (`src/attenu/`) is written against the published format
description only. It does not read, port, or invoke either attenu-guard
reference implementation.

The strict entry-field and schema-v2 record checks added in October 2026 use
the field sets that attenu-guard published on 2026-09-26 after an independent
verifier reported they could not be derived from the earlier prose. The local
v1.5 corpus now supplies published rows for several of those rules.
Agent-guard retains its own re-sealed negative mutations and full field sweeps:
agreement on these twenty-nine cases does not establish coverage of every
published field or malformed record.
