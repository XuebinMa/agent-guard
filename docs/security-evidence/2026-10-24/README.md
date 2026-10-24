# 0.2.10 published-artifact acceptance

These files retain the actual 2026-10-24 delivery observations, not a proposed
release or source-only install. Start with [the release manifest](release-0210.json)
and [human-readable scope/upgrade notes](../../release-0210-delivery.md).

- [Registry artifacts](registry-verified.json): eight crates, five wheels and
  the npm tarball, hashes, source bindings, locks and content checks.
- [Exact-run wheel checks](workflow-wheel-verification.json): workflow archive
  bytes, build-log hashes, actual Tokio compilation and embedded SBOMs. Those
  hashes match the subsequently downloaded public wheels.
- [Installed smoke](installed-smoke.json): three actual registry CLI versions,
  hook decisions, verifier corpora and the actual installed macOS arm64 wheel.
- [Authenticated CLI fixture log](registry-cli-auth.log): 13/13 passing with
  the registry-installed Broker, temporary loopback endpoints and synthetic auth.
- [npm signature log](npm-signatures.log): one registry signature and one
  attestation actually verified, not merely parsed from a statement.
- [Final-main jobs](main-jobs.json), [release jobs](release-jobs.json) and
  [public release](public-release.json): raw public API observations.
- [Native Linux report](native-linux.json),
  [Broker tests](native-broker-tests.log) and [CLI tests](native-cli-tests.log):
  exact final-main fixed synthetic Docker profile and complementary suites.
- [Final-main SBOM checks](main-sbom-verification.json): all ten extracted
  components and graph-specific Tokio/process-wrap versions. The ZIP digest is
  API-declared, not independently verified; extracted files were checked.

## Reproduction methods

The adjacent scripts are the actual temporary acceptance helpers retained for
review. They are not product entry points or a new CI gate. Original 0.2.9
helpers remain unchanged. The registry verifier refuses overwriting evidence,
caps remote/expanded data and checks only official registry endpoints. Do not
run it just to overwrite these historical observations; copy it and its
adjacent test file into a fresh temporary directory for a new observation.

Its **offline-only** controls need no credentials or network:

```bash
python3 -I -B docs/security-evidence/2026-10-24/verify_registry.py --self-test
```

All 15 controls passed after splitting the test class into the adjacent file.
That split changed no artifact-acceptance logic. A full new observation uses
`verify_registry.py --version 0.2.10 --source <checkout> --commit
2da78b1d0b4ad3e62ebc02c09a6d0dd27f836181 --run-id 40112534342 --output
<new-json-beside-script>`. Its archive checks do not install or execute code
and do not cryptographically authenticate npm provenance; the independent
installation and signature checks below supply that separate evidence.

Each actual crates.io install used a new, shared-for-this-acceptance prefix,
Cargo home and build directory, with no source-path override:

```text
CARGO_HOME=<isolated-root>/cargo-home
CARGO_TARGET_DIR=<isolated-root>/registry-target
cargo install guard-hook --version '=0.2.10' --locked --registry crates-io --root <isolated-root>/registry-install
cargo install agent-guard-cli --version '=0.2.10' --locked --registry crates-io --root <isolated-root>/registry-install
cargo install guard-verify --version '=0.2.10' --locked --registry crates-io --root <isolated-root>/registry-install
```

Both environment variables were exported to each command. The exact prefix
and the three successful logs/hashes are in the manifest. Builds reused only
this fresh acceptance's cache; a cached dependency need not appear as compiled
again in every log. `installed_smoke.py` ran under the fresh wheel venv's
`python -I` without optimization, with `--source` pointing at the immutable
release checkout, `--bin-dir` pointing at the registry install, and `--output`
choosing a new file. It only submits negative Shell strings as decision data.

The actual PyPI wheel was installed with hash-required, isolated, binary-only,
no-dependency/no-cache pip flags from the public registry. Its SHA-256 is in the
manifest and [installation log](wheel-install.log). Other platforms were checked
as archives and build logs, not executed. `verify_workflow_wheels.py` expects
the five downloaded exact-run artifacts under `workflow-wheels/` and the named
raw job logs beside it; `verify_pypi_metadata.py` then compares official metadata
against those exact wheel digests. These large inputs are not checked in: job
IDs and their hashes remain in the results, and Actions retention is finite.

For npm, the exact plugin was installed with scripts disabled into a new
prefix, using empty user/global npm configs, no auth-token environment and
the official registry. npm **11.8.0** then ran `audit signatures` with that
same prefix/config/cache. No plugin initialization or global configuration
change was executed. Its cryptographic success is independent of the verifier's
statement-field checks. The immutable repository/workflow/tag/commit/run and
tarball subject binding were checked as well.

The two native test logs and npm signature log had a final empty line that
failed `git diff --check`. Stored copies remove only that empty line, without
removing or changing any result. Their original and stored SHA-256 values are
both recorded explicitly in the manifest. All other retained logs are unchanged.

Installation logs and the native/fixture logs contain only public package
information, temporary paths and synthetic fixture identities; no credentials,
private keys or live third-party remote are retained. Local paths document the
observation and are not promised to remain on disk. This acceptance does not
upgrade the user's real deployment or expand the product's containment claims.
