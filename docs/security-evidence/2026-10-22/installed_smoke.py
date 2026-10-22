#!/usr/bin/env python3
"""Exercise only installed CLIs and wheel decision APIs; never execute shell inputs."""

import argparse
import importlib.metadata
import json
from pathlib import Path
import subprocess
import sys


def run(argv, stdin=None):
    completed = subprocess.run(
        [str(value) for value in argv], input=stdin, text=True,
        capture_output=True, timeout=60, check=False,
    )
    if completed.returncode:
        raise AssertionError(
            f"{argv[0]} failed ({completed.returncode}): {completed.stderr[-2000:]}"
        )
    return completed.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    policy = source / "presets/coding-agent-outbound.yaml"
    results = {"version": "0.2.9", "shell_inputs_executed": False, "binaries": {}}
    for name in ("guard-hook", "agent-guard", "guard-verify"):
        binary = args.bin_dir / name
        version = run([binary, "--version"]).strip()
        assert version.endswith(" 0.2.9"), version
        results["binaries"][name] = version

    cases = [
        ("echo smoke", "allow"),
        ("git push origin local-test", "ask"),
        ("sudo echo denied", "deny"),
        ("=printf visible", "deny"),
        ("ls \r#;printf visible", "deny"),
    ]
    results["hook_decisions"] = []
    for command, expected in cases:
        payload = json.dumps({
            "cwd": str(args.output.parent), "tool_name": "Bash",
            "tool_input": {"command": command},
        })
        stdout = run([args.bin_dir / "guard-hook", "check", "--policy", policy], payload)
        outputs = [json.loads(line)["hookSpecificOutput"]
                   for line in stdout.splitlines()
                   if line.startswith("{") and "hookSpecificOutput" in json.loads(line)]
        assert len(outputs) == 1, stdout
        assert outputs[0]["permissionDecision"] == expected, outputs
        results["hook_decisions"].append({"input": command, "decision": expected})

    results["corpora"] = {}
    for subcommand, filename, expected in [
        ("attenu-vectors", "bundle_vectors_v1.json", "29/29 conformant"),
        ("attenu-envelope-vectors", "envelope_vectors_v1.json", "19/19 conformant"),
    ]:
        stdout = run([args.bin_dir / "guard-verify", subcommand, "--vectors",
                      source / "crates/guard-verify/fixtures/attenu" / filename])
        assert stdout.rstrip().endswith(expected), stdout
        results["corpora"][subcommand] = expected
    help_text = run([args.bin_dir / "agent-guard", "push", "--help"])
    assert "--git-config" in help_text and "--allow-local-file-remote" in help_text
    results["broker_help_contract"] = True

    import agent_guard

    assert agent_guard.__version__ == "0.2.9"
    assert importlib.metadata.version("agent-guard-python") == "0.2.9"
    module_path = Path(agent_guard.__file__).resolve()
    assert module_path.is_relative_to(Path(sys.prefix).resolve()), module_path
    assert not module_path.is_relative_to(source), module_path
    guard = agent_guard.Guard.from_yaml(policy.read_text(encoding="utf-8"))
    results["wheel_decisions"] = []
    for command, expected in cases:
        decision = guard.check("bash", command, trust_level="trusted",
                               working_directory=str(args.output.parent))
        expected_outcome = {"allow": "allow", "deny": "deny", "ask": "ask_user"}[expected]
        assert decision.outcome == expected_outcome, (command, decision.outcome)
        results["wheel_decisions"].append({"input": command, "decision": decision.outcome})
    for yaml_text in [
        "version: 1\nversion: 1\ndefault_mode: read_only\n",
        "version: 1\naudit:\n  enabled: \"true\"\n",
    ]:
        try:
            agent_guard.Guard.from_yaml(yaml_text)
        except agent_guard.GuardError:
            pass
        else:
            raise AssertionError("installed wheel accepted an invalid policy fixture")
    results["wheel_module_path"] = str(module_path)
    results["wheel_policy_negative_checks"] = 2
    results["success"] = True
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(results, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(json.dumps({"success": True, "output": str(args.output)}))


if __name__ == "__main__":
    main()
