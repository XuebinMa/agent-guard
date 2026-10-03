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


def emit(
    scenario: dict,
    guard: "agent_guard.Guard",
    invalid_signed_guard: "agent_guard.Guard",
) -> dict:
    scenario_guard = invalid_signed_guard if scenario.get("invalid_signature") else guard
    tool = scenario["tool"]
    payload = json.dumps(scenario["payload"])
    ctx = scenario.get("context", {})
    kwargs = {}
    if "trust_level" in ctx:
        kwargs["trust_level"] = ctx["trust_level"]
    for opt in ("agent_id", "session_id", "actor", "working_directory"):
        if ctx.get(opt) is not None:
            kwargs[opt] = ctx[opt]

    decision = scenario_guard.check(tool=tool, payload=payload, **kwargs)
    runtime = scenario_guard.decide(tool=tool, payload=payload, **kwargs)

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
    with open(policy_path, "r", encoding="utf-8") as f:
        policy_yaml = f.read()
    invalid_signed_guard = agent_guard.Guard.from_signed_yaml(
        policy_yaml,
        "0000000000000000000000000000000000000000000000000000000000000001",
        "ff" * 64,
    )
    with open(scenarios_path, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    for scenario in scenarios:
        print(
            json.dumps(
                emit(scenario, guard, invalid_signed_guard), separators=(",", ":")
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
