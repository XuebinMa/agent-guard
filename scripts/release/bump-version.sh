#!/usr/bin/env bash
#
# Bump live source-version markers from the workspace Cargo version without
# changing the separately tracked latest-published-release markers.
#
# Usage:
#   scripts/release/bump-version.sh <new-version>
#   scripts/release/bump-version.sh --check    # print current version and exit
#
# After bumping, `scripts/check-version-consistency.sh` (also run by
# `scripts/verify.sh docs`) verifies nothing drifted.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <new-version> | --check" >&2
  exit 2
fi

NEW_VERSION="$1"

if [[ "$NEW_VERSION" == "--check" ]]; then
  exec python3 "$ROOT_DIR/scripts/version_markers.py" current --root "$ROOT_DIR"
fi

python3 "$ROOT_DIR/scripts/version_markers.py" bump "$NEW_VERSION" --root "$ROOT_DIR"
echo
echo "Next steps: review the diff, update CHANGELOG.md by hand, then commit."
