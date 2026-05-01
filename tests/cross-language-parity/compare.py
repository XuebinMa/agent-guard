"""Cross-language parity comparator.

Runs the Rust, Python, and Node parity runners against the shared fixtures,
parses their JSONL output, and asserts that all three produce identical
results per scenario. Exits 0 on identity, non-zero with a diff on any
divergence.

Usage:
    python tests/cross-language-parity/compare.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FIXTURES = os.path.join(ROOT, "tests", "cross-language-parity", "fixtures")
RUNNERS = os.path.join(ROOT, "tests", "cross-language-parity", "runners")
POLICY = os.path.join(FIXTURES, "policy.yaml")
SCENARIOS = os.path.join(FIXTURES, "scenarios.json")


def run(cmd: list[str], cwd: str = ROOT) -> str:
    proc = subprocess.run(
        cmd, cwd=cwd, check=False, capture_output=True, text=True
    )
    if proc.returncode != 0:
        sys.stderr.write(f"$ {' '.join(cmd)}\nstderr:\n{proc.stderr}\n")
        raise SystemExit(f"runner exited {proc.returncode}: {' '.join(cmd)}")
    return proc.stdout


def parse_jsonl(text: str) -> dict[str, dict]:
    """Map scenario name → result dict."""
    out: dict[str, dict] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        out[rec["name"]] = rec
    return out


def diff(label: str, a: dict, b: dict) -> list[str]:
    names = sorted(set(a) | set(b))
    diffs: list[str] = []
    for name in names:
        if name not in a:
            diffs.append(f"  [{name}] missing from rust ({label})")
            continue
        if name not in b:
            diffs.append(f"  [{name}] missing from {label}")
            continue
        if a[name] != b[name]:
            diffs.append(
                f"  [{name}] rust={a[name]} {label}={b[name]}"
            )
    return diffs


def main() -> int:
    print(f"using POLICY={POLICY}")
    print(f"using SCENARIOS={SCENARIOS}")

    rust_out = run(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "agent-guard-sdk",
            "--example",
            "parity_runner",
            "--",
            POLICY,
            SCENARIOS,
        ]
    )
    py_out = run([sys.executable, os.path.join(RUNNERS, "runner.py"), POLICY, SCENARIOS])
    node_out = run(["node", os.path.join(RUNNERS, "runner.js"), POLICY, SCENARIOS])

    rust = parse_jsonl(rust_out)
    py = parse_jsonl(py_out)
    node = parse_jsonl(node_out)

    print(f"rust scenarios: {len(rust)}")
    print(f"python scenarios: {len(py)}")
    print(f"node scenarios: {len(node)}")

    py_diffs = diff("python", rust, py)
    node_diffs = diff("node", rust, node)

    if py_diffs:
        print("\n--- python divergences ---")
        for d in py_diffs:
            print(d)
    if node_diffs:
        print("\n--- node divergences ---")
        for d in node_diffs:
            print(d)

    if py_diffs or node_diffs:
        return 1

    print(f"\nOK — {len(rust)} scenarios match across rust / python / node")
    return 0


if __name__ == "__main__":
    sys.exit(main())
