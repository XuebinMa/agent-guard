# `agent-guard-unwrap-v1` normalization annex + conformance vectors

Deliverable for crewAI #5888 / PR #6030: agent-guard's shell command-body
normalization, offered as the `agent-guard-unwrap-v1` profile that the
governance contract references for the `normalized command body` field. Accepted
by the contract author (nagasatish007) and architect (safal207) on 2026-06-25 as
a referenced normalization annex.

## Contents

- **`agent-guard-unwrap-v1.md`** — the annex spec: the unwrap algorithm + the
  wrapper table, transcribed from agent-guard's shipped gate
  (`crates/agent-guard-validators/src/bash/wrappers.rs`).
- **`vectors.json`** — test-2 / test-3 conformance vectors (equivalence classes,
  divergence pairs, target-hiding fail-closed cases).
- **`normalize_check.py`** — a dependency-light second implementation of the
  profile; recomputes the digests and asserts all three properties.
- **`fidelity/`** — a Rust harness that proves the documented profile matches
  agent-guard's *real* gate verdicts (public API only; no production-code change).

## Run

```sh
# 1. Digest-level conformance (reference re-implementation, stdlib + rfc8785)
python3 -m venv .venv && ./.venv/bin/pip install rfc8785
./.venv/bin/python normalize_check.py            # exit 0 = all properties held

# 2. Fidelity to the shipped gate (real validate_bash_command)
cd fidelity && cargo run                          # "gate fidelity confirmed", exit 0
```

`normalize_check.py` proves equivalence/divergence/fail-closed at the digest
level from committed bytes. The Rust harness proves every wrapped form tracks the
bare canonical command's gate verdict (wrappers transparent) and that
target-hiding spawners block in `WorkspaceWrite`.

## What this is / isn't

This is a standalone spike (the `fidelity/` crate has its own `[workspace]`
root): it adds no dependencies to the shipped agent-guard crates and changes no
production code — the normalization is *transcribed from* and *validated against*
the existing gate. The profile covers the shell/command-body case only;
structured tool arguments use a different `normalization_id` (JCS-over-args).
