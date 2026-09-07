# Third-party interoperability corpus

`bundle_vectors_v1.json` is vendored verbatim from
[`attenu-io/attenu-guard`](https://github.com/attenu-io/attenu-guard),
`tests/vectors/bundles/bundle_vectors_v1.json`, which is licensed
Apache-2.0. It is unmodified.

- revision: the `bundle_vectors_v1.2` corpus shipped in attenu-guard 0.12.1, taken at tag `v0.12.1`
- size: 146,765 bytes
- sha256: `54311d68c8342c01ce233f4b1aea251125a4f3323fd9776c01843d3b2f5700ea`

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
