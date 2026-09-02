# Third-party interoperability corpus

`bundle_vectors_v1.json` is vendored verbatim from
[`attenu-io/attenu-guard`](https://github.com/attenu-io/attenu-guard),
`tests/vectors/bundles/bundle_vectors_v1.json`, which is licensed
Apache-2.0. It is unmodified.

- size: 69,573 bytes
- sha256: `90d7fa70eabe92cbfa4df04bad50ac78995b57e83812cc5671e1ba9de01619ce`

The same bytes ship inside the released `attenu-guard 0.11.0` wheel as
`attenu_guard.vectors.load_bundle_vectors()`, and the file is the same git
blob (`7a78f025eed9f219f2ee055cef3ec1ae3fe1f352`) in the Python `v0.11.0` and
TypeScript `v0.6.0` tags.

It is vendored rather than fetched so the conformance test is hermetic and
so the bytes under test cannot drift. `attenu_corpus_fixture_bytes_are_pinned`
in `src/attenu/tests.rs` fails if this file changes.

Our verifier (`src/attenu/`) is written against the published format
description only. It does not read, port, or invoke either attenu-guard
reference implementation.
