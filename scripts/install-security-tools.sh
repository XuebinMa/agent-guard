#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: $0 cargo-deny|cargo-audit|cargo-cyclonedx [...]" >&2
  exit 2
fi

for tool in "$@"; do
  case "$tool" in
    cargo-deny)
      cargo install cargo-deny --version 0.19.4 --locked
      ;;
    cargo-audit)
      cargo install cargo-audit --version 0.22.1 --locked
      ;;
    cargo-cyclonedx)
      cargo install cargo-cyclonedx --version 0.5.9 --locked
      ;;
    *)
      echo "unsupported security tool: $tool" >&2
      exit 2
      ;;
  esac
done
