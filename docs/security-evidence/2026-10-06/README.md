# Decision-only parser evidence

Baseline: `e1a0a0a5fd956186e67e9c235451cbfa2fb4b260`.

These retained session artifacts preserve the original lower-level diagnostic
and the other reviewer's uncommitted four-file proposal. The original checkout
was not modified. All negative Shell strings were classified as data; none was
executed. Logs may contain temporary absolute paths that are no longer present.

- `decision-diagnostics.rs`: the five standalone decision-only tests.
- `baseline.log`: diagnostic results on the original source.
- `supplied-control-parser.patch.b64`: byte-preserving Base64 archive of the
  original partial proposal, not the final repair or an executable script.
  Decode as data if comparison is needed; do not apply it as the final repair.
  Archival encoding preserves unified-diff space-only context lines without
  introducing trailing whitespace into this repository's own staged diff.
- `patch.log`: three passing and two failing diagnostics for that proposal.

Permanent regressions and new-tree verification supersede these dated artifacts.
They do not prove a real shell, SDK or credential-bearing broker bypass by
themselves; the new real SDK tests record their own decision results separately.
