# CLAUDE.md — agent-guard-python

Scoped guidance for the PyO3 binding. This **adds** to the root
[`CLAUDE.md`](../../CLAUDE.md); it does not repeat it.

## The extension-module trap (read this first)

This crate has one footgun that will waste your time if you miss it. The
`extension-module` feature switches PyO3 into "don't link libpython" mode, which
is required to build a loadable Python module but **breaks a normal workspace
build/test** (the binary has no Python symbols to link against).

So there are two mutually exclusive modes:

- **Workspace build/test** → `extension-module` **off**. This is why every
  workspace command excludes this crate:
  ```bash
  cargo build --workspace --exclude agent-guard-python --all-features
  cargo test  --workspace --exclude agent-guard-python --all-features
  ```
- **Building the actual Python module for binding tests** → `extension-module`
  **on**, driven by maturin inside a venv, never by a bare `cargo build`:
  ```bash
  cd crates/agent-guard-python && maturin develop --features extension-module
  pytest tests/ -v
  ```

`./scripts/verify.sh python` does the venv + maturin + pytest dance for you in a
throwaway environment; prefer it over running the steps by hand.

## Crate shape

- `crate-type = ["cdylib"]`, lib name `agent_guard`, built against
  `abi3-py310` — one wheel covers CPython 3.10+.
- Rust surface lives in `src/`; pure-Python adapters live in
  `python/agent_guard/` (`langchain.py`, `openai.py`, `adapters.py`).
- Any decision-shaped object returned to Python goes through
  `_decision_to_error_attrs` — keep new adapter paths on that helper so error
  attributes stay uniform.
- Type stubs track the `#[pyclass]` definitions. If you add or rename a pyclass
  field or method, update the stub in the same change — nothing regenerates it
  for you.

## This binding is a parity runner

`agent-guard-python` is one of the three cross-language parity surfaces. A
change to decision shape, `DecisionCode`, or `check`/`decide`/`run`/`execute`
semantics here is only correct if the Rust core and the Node binding change with
it and the parity scenarios still pass. See
[Cross-Language Parity](../../docs/concepts/cross-language-parity.md),
[Adapter Contract](../../docs/concepts/adapter-contract.md), and the parity
section of the [Testing Strategy](../../docs/concepts/testing-strategy.md).

## Tests

`tests/*.py` (pytest): `test_guard.py`, `test_runtime.py`,
`test_langchain_adapter.py`, `test_openai_adapter.py`,
`test_real_frameworks.py`. They run against a real built module — do not stub
the native layer; build it with maturin and test the real surface.
`test_real_frameworks.py` additionally needs real `langchain-core` installed
and skips otherwise; the CI `python-framework-test` job matrixes it over
framework versions via `AGENT_GUARD_PY_FRAMEWORKS` (see `scripts/verify.sh`).
Cross-language obligations are in [`CONTRIBUTING.md`](../../CONTRIBUTING.md).
</content>
