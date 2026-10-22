# 0.2.9 release acceptance evidence

[release-029.json](release-029.json) records the immutable source/tag, exact
CI runs, downloaded package hashes and contents, actual isolated installations,
safe decision/corpus smokes and the independent npm signature result. See the
[delivery narrative](../../release-029-delivery.md) for scope and compatibility.
The published tag remains on the release source, not this later record commit.

## Reproduce the read-only artifact checks

The frozen [registry verifier](verify_registry.py) uses only the Python standard
library (Python 3.11+). It restricts HTTPS hosts, redirects, byte/time budgets
and archive members; it never extracts archives to disk or runs package code.
Its output must be a new JSON file beside the script. Run from an isolated
copy so a fresh observation does not replace the dated evidence:

```bash
release_check_dir=$(mktemp -d /private/tmp/agent-guard-029-check.XXXXXX)
cp docs/security-evidence/2026-10-22/verify_registry.py "$release_check_dir/"
python3 -I "$release_check_dir/verify_registry.py" --self-test
python3 -I "$release_check_dir/verify_registry.py" \
  --version 0.2.9 \
  --commit 8f29c88f40218ed289d115106bee00556a7a23e6 \
  --run-id 39830348740 \
  --output "$release_check_dir/registry-check.json"
```

The nine offline tests include checksum/subject mismatches, unsafe archive
paths, non-public download targets, non-exact internal pins, missing wrapper
modules, definitive absence handling and the exact official crate archive URL.
The first delivery attempt negotiated a JSON download-location response from
crates.io's API and correctly failed its archive checksum. The corrected tool
downloads the exact official static archive and retains the checksum checks;
no product artifact or security gate was changed to make it pass.

The SLSA statement check matches tarball digest, repository, workflow, tag,
commit and release-run identity, but is not a cryptographic verification.
The separate actual `npm audit signatures` result verified one registry
signature and one attestation using npm 11.8.0 after an isolated installation
with scripts disabled. This verifier does not substitute for that command.

## Actual installed-package checks

Three CLI packages were installed from crates.io, not a local source path,
using an empty isolated Cargo home, target and installation prefix:

```text
cargo install <guard-hook|agent-guard-cli|guard-verify> \
  --version '=0.2.9' --locked --registry crates-io --root <isolated-prefix>
```

The actual PyPI macOS arm64 wheel was installed into a fresh Python 3.14 venv
with `--isolated --no-deps --only-binary=:all: --require-hashes`, using the exact
SHA-256 in the JSON. Its module was within that venv and outside the checkout.
The [installed smoke driver](installed_smoke.py) takes explicit installed-bin,
source-fixture and output paths. It checks versions, passes synthetic strings
only to decision APIs, runs the two offline corpora and checks parser refusals.
It does not execute those shell strings, push Git changes or test credentials.

The log digests identify the operator's local logs; those logs are not promised
to remain in a temporary directory. The reproducible inputs, package hashes,
results and method are retained here. Registry availability and provenance
endpoints can change; a later verification failure is not proof that the dated
observation never occurred.

Only macOS arm64's installed wheel was executed. Five-platform content/RECORD
checks and hosted CI are not five-platform installed-wheel execution. The
fixed native Linux container result is not arbitrary-host containment, and
neither these checks nor receipts establish credential or human isolation.
