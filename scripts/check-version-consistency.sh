#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_cmd python3

read_versions() {
  python3 - "$ROOT_DIR" <<'PY'
from pathlib import Path
import json
import re
import sys
import tomllib

root = Path(sys.argv[1])

def read_toml(path: Path):
    with path.open("rb") as fh:
        return tomllib.load(fh)

cargo_version = read_toml(root / "Cargo.toml")["workspace"]["package"]["version"]
node_version = json.loads((root / "crates/agent-guard-node/package.json").read_text())["version"]
python_version = read_toml(root / "crates/agent-guard-python/pyproject.toml")["project"]["version"]

readme = (root / "README.md").read_text()
docs_readme = (root / "docs/README.md").read_text()

badge_match = re.search(r"Version-([0-9A-Za-z.\-]+)-blue", readme)
release_match = re.search(r"releases/tag/v([0-9A-Za-z.\-]+)", readme)
docs_title_match = re.search(r"Documentation Hub \(v([0-9A-Za-z.\-]+)\)", docs_readme)
docs_release_match = re.search(r"releases/tag/v([0-9A-Za-z.\-]+)", docs_readme)

if not all([badge_match, release_match, docs_title_match, docs_release_match]):
    missing = []
    if not badge_match:
        missing.append("README badge version")
    if not release_match:
        missing.append("README release version")
    if not docs_title_match:
        missing.append("docs/README title version")
    if not docs_release_match:
        missing.append("docs/README release version")
    raise SystemExit("Missing version markers: " + ", ".join(missing))

print(cargo_version)
print(node_version)
print(python_version)
print(badge_match.group(1).replace("--", "-"))
print(release_match.group(1))
print(docs_title_match.group(1))
print(docs_release_match.group(1))
PY
}

versions=()
while IFS= read -r line; do
  versions+=("$line")
done < <(read_versions)

expected="${versions[0]}"
checks=(
  "Cargo.toml:${versions[0]}"
  "crates/agent-guard-node/package.json:${versions[1]}"
  "crates/agent-guard-python/pyproject.toml:${versions[2]}"
  "README badge:${versions[3]}"
  "README release link:${versions[4]}"
  "docs/README title:${versions[5]}"
  "docs/README release link:${versions[6]}"
)

for check in "${checks[@]}"; do
  label="${check%%:*}"
  actual="${check#*:}"
  if [[ "$actual" != "$expected" ]]; then
    echo "Version mismatch for $label: expected $expected, got $actual" >&2
    exit 1
  fi
done

echo "Version consistency check passed: $expected"
