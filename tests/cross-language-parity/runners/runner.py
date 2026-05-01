"""Cross-language parity runner — Python side.

Reads policy.yaml + scenarios.json, runs each scenario through
``Guard.check`` and ``Guard.decide``, prints one JSONL line per scenario
in the same shape the Rust runner emits. The compare script does the
identity check downstream.

Usage:
    python tests/cross-language-parity/runners/runner.py \
        tests/cross-language-parity/fixtures/policy.yaml \
        tests/cross-language-parity/fixtures/scenarios.json
"""

from __future__ import annotations

import json
import sys

import agent_guard


def emit(scenario: dict, guard: "agent_guard.Guard") -> dict:
    tool = scenario["tool"]
    payload = json.dumps(scenario["payload"])
    ctx = scenario.get("context", {})
    kwargs = {
        "trust_level": ctx.get("trust_level", "untrusted"),
    }
    for opt in ("agent_id", "session_id", "actor", "working_directory"):
        if ctx.get(opt) is not None:
            kwargs[opt] = ctx[opt]

    decision = guard.check(tool=tool, payload=payload, **kwargs)
    runtime = guard.decide(tool=tool, payload=payload, **kwargs)

    return {
        "name": scenario["name"],
        "decision": decision.outcome,
        "code": decision.code,
        "runtime_decision": runtime.outcome,
        "runtime_code": runtime.code,
    }


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: runner.py <policy.yaml> <scenarios.json>", file=sys.stderr)
        return 2
    policy_path, scenarios_path = sys.argv[1], sys.argv[2]

    guard = agent_guard.Guard.from_yaml_file(policy_path)
    with open(scenarios_path, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    for scenario in scenarios:
        print(json.dumps(emit(scenario, guard), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
