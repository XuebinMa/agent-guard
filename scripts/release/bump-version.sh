#!/usr/bin/env bash
#
# Bump the project version from a single source of truth.
#
# The workspace `Cargo.toml` `[workspace.package].version` is the canonical
# version. This script reads the current value, then rewrites every other place
# the *current* version is mirrored so they stay in lockstep. It only touches
# live "current version" locations — historical references (CHANGELOG entries,
# release notes) are intentionally left alone.
#
# Usage:
#   scripts/release/bump-version.sh <new-version>
#   scripts/release/bump-version.sh --check    # print current version and exit
#
# After bumping, `scripts/check-version-consistency.sh` (also run by
# `scripts/verify.sh docs`) verifies nothing drifted.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}
require_cmd python3

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <new-version> | --check" >&2
  exit 2
fi

NEW_VERSION="$1"

python3 - "$ROOT_DIR" "$NEW_VERSION" <<'PY'
import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1])
new = sys.argv[2]

# Canonical source: workspace Cargo.toml.
with (root / "Cargo.toml").open("rb") as fh:
    old = tomllib.load(fh)["workspace"]["package"]["version"]

if new == "--check":
    print(old)
    sys.exit(0)

if new == old:
    print(f"version already {old}; nothing to do")
    sys.exit(0)

# Live "current version" locations. Each entry is (path, replacements), where a
# replacement is a literal (from -> to) substring swap. Historical files
# (CHANGELOG.md, docs/archive/release-notes-*, CLAUDE.md) are NOT listed: their
# version references are point-in-time and must not move.
def plain(p):
    return (p, [(old, new)])

# README badge uses shields.io escaping: each `-` in the version is doubled
# (`0.2.0-rc1` -> `0.2.0--rc1`). Handle that form plus the plain release link.
badge_old = old.replace("-", "--")
badge_new = new.replace("-", "--")

targets = [
    plain("Cargo.toml"),
    plain("pyproject.toml"),
    plain("crates/agent-guard-sdk/Cargo.toml"),
    plain("crates/agent-guard-sandbox/Cargo.toml"),
    plain("crates/agent-guard-validators/Cargo.toml"),
    plain("crates/agent-guard-cli/Cargo.toml"),
    plain("crates/guard-verify/Cargo.toml"),
    plain("crates/guard-hook/Cargo.toml"),
    plain("crates/agent-guard-node/Cargo.toml"),
    plain("crates/agent-guard-python/Cargo.toml"),
    plain("crates/agent-guard-node/package.json"),
    plain("crates/agent-guard-node/package-lock.json"),
    plain("crates/agent-guard-python/pyproject.toml"),
    plain("docs/README.md"),
    plain(".claude-plugin/plugin.json"),
    plain(".claude-plugin/marketplace.json"),
    plain("packages/agent-guard-plugin/package.json"),
    ("README.md", [(f"Version-{badge_old}-blue", f"Version-{badge_new}-blue"), (old, new)]),
]

changed = []
missing = []
for rel, repls in targets:
    path = root / rel
    if not path.exists():
        missing.append(rel)
        continue
    text = path.read_text()
    updated = text
    for frm, to in repls:
        updated = updated.replace(frm, to)
    if updated != text:
        path.write_text(updated)
        changed.append(rel)

print(f"bumped {old} -> {new}")
for rel in changed:
    print(f"  updated {rel}")
if missing:
    print("WARNING: expected files not found:", file=sys.stderr)
    for rel in missing:
        print(f"  {rel}", file=sys.stderr)
unchanged = [rel for rel, _ in targets if rel not in changed and rel not in missing]
if unchanged:
    print("note: no occurrence of the old version in:")
    for rel in unchanged:
        print(f"  {rel}")
PY

if [[ "$NEW_VERSION" == "--check" ]]; then
  exit 0
fi

echo
echo "Verifying consistency..."
"$ROOT_DIR/scripts/check-version-consistency.sh"
echo
echo "Next steps: review the diff, update CHANGELOG.md by hand, then commit."
