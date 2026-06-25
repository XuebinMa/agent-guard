#!/usr/bin/env python3
"""Reference implementation + conformance checker for `agent-guard-unwrap-v1`.

A dependency-light second implementation of agent-guard's transparent-wrapper /
spawner unwrap normalization (faithfully transcribed from
crates/agent-guard-validators/src/bash/wrappers.rs). It reads vectors.json and,
for each pre-tokenized argv, recomputes:

  normalized_argv      the real executable + argv after stripping NAME=value
                       prefixes and transparent wrapper/spawner layers
  normalized_digest    "sha256:" + hex(SHA-256(JCS(normalized_argv)))
  target_unverifiable  True when a target-hiding spawner (xargs / find -exec)
                       supplies the operands from stdin / the filesystem, so the
                       write target cannot be verified at authorization time

Then it checks the three conformance properties:

  test-3 equivalence  every surface form of an equivalence class normalizes to
                      the same body and the same digest (= the canonical form)
  test-2 divergence   each divergence pair normalizes to *different* digests
  test-2 fail-closed  each target-hiding input is flagged target_unverifiable

Imports only the standard library plus `rfc8785` (RFC 8785 / JCS). It does not
import agent-guard; the Rust fidelity harness separately proves the documented
normalization matches the shipped gate's real verdicts.

Run: python normalize_check.py    (exit 0 = every property held)
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import rfc8785

HERE = Path(__file__).resolve().parent

# --- Wrapper table, transcribed verbatim from wrappers.rs COMMAND_WRAPPERS ---
# name -> (short option chars that consume the FOLLOWING token, leading operands)
WRAPPERS: dict[str, tuple[set[str], int]] = {
    "sudo": (set("CDghpRrtTUu"), 0),
    "doas": (set("uC"), 0),
    "env": (set("uC"), 0),
    "nice": (set("n"), 0),
    "nohup": (set(), 0),
    "timeout": (set("sk"), 1),
    "strace": (set("oepEsa"), 0),
    "ltrace": (set("oepsau"), 0),
    "nsenter": (set("tSG"), 0),
    "unshare": (set(), 0),
    "watch": (set("n"), 0),
    "flock": (set("wE"), 1),
    "xargs": (set("IiEednPsaLl"), 0),
}


def is_env_assignment(token: str) -> bool:
    """`NAME=value` prefix: the run before the first `=` is `[A-Za-z0-9_]` only."""
    if "=" not in token:
        return False
    name = token.split("=", 1)[0]
    return all(c.isascii() and (c.isalnum() or c == "_") for c in name)


def skip_wrapper_tokens(args: list[str], flags: set[str], operands: int) -> int:
    """Tokens to drop within `args` (the slice after the wrapper name)."""
    idx = 0
    while idx < len(args):
        token = args[idx]
        if token == "--":
            idx += 1
            break
        if not token.startswith("-") or token == "-":
            break
        if token.startswith("--"):
            idx += 1
            continue
        flag_chars = list(token[1:])
        pos = next((i for i, c in enumerate(flag_chars) if c in flags), None)
        if pos is not None and pos + 1 == len(flag_chars):
            idx += 2  # arg-taking flag is last in the bundle -> value is next token
        else:
            idx += 1
    for _ in range(operands):
        if idx < len(args):
            idx += 1
    return idx


def unwrap(tokens: list[str]) -> list[str]:
    """Strip NAME=value prefixes and transparent wrapper/spawner layers."""
    s = list(tokens)
    while True:
        start = 0
        while start < len(s) and is_env_assignment(s[start]):
            start += 1
        s = s[start:]
        if not s:
            return s
        first = s[0]
        if first == "find":
            pos = next(
                (i for i, t in enumerate(s) if t in ("-exec", "-execdir")), None
            )
            if pos is not None:
                sub = s[pos + 1 :]
                end = next(
                    (i for i, t in enumerate(sub) if t in (";", "+")), len(sub)
                )
                s = sub[:end]
                continue
            return s
        if first not in WRAPPERS:
            return s  # real command word reached
        flags, operands = WRAPPERS[first]
        skipped = 1 + skip_wrapper_tokens(s[1:], flags, operands)
        s = s[min(skipped, len(s)) :]


def leads_with_target_hiding_spawner(tokens: list[str]) -> bool:
    """xargs (operands from stdin) or find -exec (operands from the FS traversal)."""
    i = 0
    while i < len(tokens) and is_env_assignment(tokens[i]):
        i += 1
    if i >= len(tokens):
        return False
    if tokens[i] == "xargs":
        return True
    if tokens[i] == "find":
        return any(t in ("-exec", "-execdir") for t in tokens[i:])
    return False


def digest(normalized_argv: list[str]) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(normalized_argv)).hexdigest()


def main() -> int:
    vectors = json.loads((HERE / "vectors.json").read_text())
    ok = True

    def check(label: str, cond: bool) -> None:
        nonlocal ok
        ok = ok and cond
        print(f"[{'OK' if cond else 'FAIL'}] {label}")

    # test-3: equivalence classes normalize to one body + one digest
    for cls in vectors["equivalence_classes"]:
        canon = unwrap(cls["canonical_argv"])
        canon_dig = digest(canon)
        for form in cls["forms"]:
            n = unwrap(form)
            check(
                f"equiv {cls['name']}: {form} -> {n}",
                n == canon and digest(n) == canon_dig,
            )

    # test-2: divergence pairs produce different digests
    for i, pair in enumerate(vectors["divergence_pairs"]):
        da, db = digest(unwrap(pair["a"])), digest(unwrap(pair["b"]))
        check(f"divergence[{i}]: a != b digest", da != db)

    # test-2: target-hiding spawners flagged unverifiable (fail closed)
    for case in vectors["fail_closed_target_hiding"]:
        check(
            f"fail-closed: {case['argv']} target_unverifiable",
            leads_with_target_hiding_spawner(case["argv"]),
        )

    print("\n" + ("all properties held" if ok else "CONFORMANCE FAILURE"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
