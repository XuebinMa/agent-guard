#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: ./scripts/verify.sh [full|rust|lint|python|node|docs]

Commands:
  full    Run the active local verification path
  rust    Build and test the Rust workspace, excluding agent-guard-python
  lint    Run rustfmt and clippy on the Rust workspace, excluding agent-guard-python
  python  Build and test the Python binding through maturin
  node    Build and test the Node binding
  docs    Run docs and version-consistency checks
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

run_rust() {
  require_cmd cargo
  cargo build --workspace --exclude agent-guard-python --all-features
  cargo test --workspace --exclude agent-guard-python --all-features
}

run_lint() {
  require_cmd cargo
  cargo fmt --all -- --check
  cargo clippy --workspace --exclude agent-guard-python --all-features -- -D warnings
}

run_python() {
  require_cmd python3
  require_cmd cargo

  local tmpdir
  local venv_python
  local venv_maturin
  local venv_pytest
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/agent-guard-python-verify.XXXXXX")"
  trap 'rm -rf "$tmpdir"' RETURN

  python3 -m venv "$tmpdir/venv"
  venv_python="$tmpdir/venv/bin/python"
  venv_maturin="$tmpdir/venv/bin/maturin"
  venv_pytest="$tmpdir/venv/bin/pytest"

  "$venv_python" -m pip install --upgrade pip
  "$venv_python" -m pip install maturin pytest

  pushd "$ROOT_DIR/crates/agent-guard-python" >/dev/null
  env -u CONDA_DEFAULT_ENV -u CONDA_PREFIX \
    VIRTUAL_ENV="$tmpdir/venv" \
    PATH="$tmpdir/venv/bin:$PATH" \
    "$venv_maturin" develop --features extension-module
  env -u CONDA_DEFAULT_ENV -u CONDA_PREFIX \
    VIRTUAL_ENV="$tmpdir/venv" \
    PATH="$tmpdir/venv/bin:$PATH" \
    "$venv_pytest" tests/ -v
  popd >/dev/null
}

run_node() {
  require_cmd npm
  pushd "$ROOT_DIR" >/dev/null
  npm ci --prefix crates/agent-guard-node
  npm run build:debug --prefix crates/agent-guard-node
  npm test --prefix crates/agent-guard-node
  popd >/dev/null
}

run_docs() {
  require_cmd python3
  "$ROOT_DIR/scripts/check-version-consistency.sh"
  python3 "$ROOT_DIR/scripts/check_docs.py"
}

command="${1:-full}"

pushd "$ROOT_DIR" >/dev/null
case "$command" in
  full)
    run_docs
    run_lint
    run_rust
    run_python
    run_node
    ;;
  rust)
    run_rust
    ;;
  lint)
    run_lint
    ;;
  python)
    run_python
    ;;
  node)
    run_node
    ;;
  docs)
    run_docs
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
popd >/dev/null
