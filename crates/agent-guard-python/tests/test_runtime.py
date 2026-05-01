"""
Runtime-API parity tests for the Python binding.

Covers the Sprint 3 S3-2 surface that brings the Python bindings to
runtime-API parity with the Node bindings:

  * ``Guard.decide``                    -> ``RuntimeDecision``
  * ``Guard.run``                       -> ``RuntimeOutcome``
  * ``Guard.report_handoff_result``     -> emits ``ExecutionFinished`` audit

Run with (after `maturin develop`):

    pytest crates/agent-guard-python/tests/test_runtime.py -v
"""

import json
import time
from pathlib import Path

import pytest

import agent_guard


# ── Policy fixtures ───────────────────────────────────────────────────────────

# Default policy used for the in-memory decide/run cases. workspace_write so
# bash echo is allowed, ask rule for git push, deny rule for rm -rf.
RUNTIME_POLICY = """
version: 1
default_mode: workspace_write

tools:
  bash:
    deny:
      - prefix: "rm -rf"
    ask:
      - prefix: "git push"
    allow:
      - prefix: "echo"
      - prefix: "ls"

  read_file:
    allow_paths:
      - "/**"

  http_request:
    allow:
      - prefix: "https://example.com"
"""


@pytest.fixture(scope="module")
def guard():
    return agent_guard.Guard.from_yaml(RUNTIME_POLICY)


# ── Guard.decide → RuntimeDecision (4 shapes) ─────────────────────────────────


def test_decide_returns_execute_for_allowed_bash(guard):
    d = guard.decide("bash", "echo runtime", trust_level="trusted")
    assert isinstance(d, agent_guard.RuntimeDecision)
    assert d.outcome == "execute"
    assert d.is_execute()
    assert d.code is None
    assert d.message is None
    assert d.policy_version == guard.policy_version()
    assert d.policy_verification_status == "unsigned"


def test_decide_returns_handoff_for_read_file(guard):
    payload = json.dumps({"path": "/workspace/README.md"})
    d = guard.decide("read_file", payload, trust_level="trusted")
    assert isinstance(d, agent_guard.RuntimeDecision)
    assert d.outcome == "handoff"
    assert d.is_handoff()
    # Handoff carries no reason/message
    assert d.code is None
    assert d.message is None
    assert d.ask_prompt is None


def test_decide_returns_deny_for_blocked_bash(guard, tmp_path):
    # `rm -rf /` writes outside the configured workspace; the bash validator
    # blocks before the policy rules even get a chance to weigh in. The
    # working_directory pins a real workspace so the path-escape check fires
    # (otherwise the default "." workspace lets the destructive check
    # downgrade this to ask_for_approval).
    d = guard.decide(
        "bash",
        "rm -rf /",
        trust_level="trusted",
        working_directory=str(tmp_path),
    )
    assert isinstance(d, agent_guard.RuntimeDecision)
    assert d.outcome == "deny"
    assert d.is_deny()
    assert d.code is not None
    assert d.message is not None


def test_decide_returns_ask_for_approval_for_ask_rule(guard):
    d = guard.decide("bash", "git push origin main", trust_level="trusted")
    assert isinstance(d, agent_guard.RuntimeDecision)
    assert d.outcome == "ask_for_approval"
    assert d.is_ask_for_approval()
    assert d.code is not None
    assert d.message is not None
    assert d.ask_prompt is not None


# ── Guard.run → RuntimeOutcome (4 shapes) ─────────────────────────────────────


def test_run_executes_allowed_bash(guard):
    outcome = guard.run("bash", "echo run-smoke", trust_level="trusted")
    assert isinstance(outcome, agent_guard.RuntimeOutcome)
    assert outcome.outcome == "executed"
    assert outcome.is_executed()
    assert outcome.request_id  # non-empty UUID-ish string
    assert outcome.output is not None
    assert "run-smoke" in outcome.output.stdout
    assert outcome.output.exit_code == 0
    assert outcome.sandbox_type is not None
    assert outcome.policy_version == guard.policy_version()
    # Executed has no decision payload (it is the "happy path" result).
    assert outcome.decision is None


def test_run_returns_denied_for_destructive_command(guard, tmp_path):
    # See note on test_decide_returns_deny_for_blocked_bash: working_directory
    # is required so the bash validator's path-escape check produces Deny
    # instead of ask_for_approval.
    outcome = guard.run(
        "bash",
        "rm -rf /",
        trust_level="trusted",
        working_directory=str(tmp_path),
    )
    assert isinstance(outcome, agent_guard.RuntimeOutcome)
    assert outcome.outcome == "denied"
    assert outcome.is_denied()
    assert outcome.request_id
    assert outcome.output is None
    assert outcome.decision is not None
    assert outcome.decision.outcome == "deny"
    assert outcome.decision.is_deny()
    assert outcome.decision.code is not None
    assert outcome.decision.message is not None


def test_run_returns_ask_for_approval_for_ask_rule(guard):
    outcome = guard.run("bash", "git push origin main", trust_level="trusted")
    assert isinstance(outcome, agent_guard.RuntimeOutcome)
    assert outcome.outcome == "ask_for_approval"
    assert outcome.is_ask_for_approval()
    assert outcome.request_id
    assert outcome.output is None
    assert outcome.decision is not None
    assert outcome.decision.outcome == "ask_for_approval"
    assert outcome.decision.ask_prompt is not None


def test_run_returns_handoff_for_read_file(guard):
    """The Handoff path is the contract that S3-2 brings to Python.

    A `read_file` for a non-mutation read goes through the runtime as
    Handoff -- the SDK does NOT execute it; the host does. The test must
    therefore land on `RuntimeOutcome::Handoff` (not Executed and not
    Denied), which is the branch this assertion covers.
    """
    payload = json.dumps({"path": "/workspace/README.md"})
    outcome = guard.run("read_file", payload, trust_level="trusted")
    assert isinstance(outcome, agent_guard.RuntimeOutcome)
    assert outcome.outcome == "handoff"
    assert outcome.is_handoff()
    assert outcome.request_id  # used to close the audit loop
    assert outcome.output is None
    # Mirrors the Node binding: the Handoff outcome surfaces a `decision`
    # with outcome="handoff" so consumers branching on `decision.outcome`
    # keep working.
    assert outcome.decision is not None
    assert outcome.decision.outcome == "handoff"
    assert outcome.decision.is_handoff()


# ── Guard.report_handoff_result → ExecutionFinished audit ─────────────────────


def _build_audit_policy(audit_path: Path) -> str:
    """Build a runtime policy whose audit stream is JSONL on disk."""
    return f"""
version: 1
default_mode: workspace_write

audit:
  enabled: true
  output: file
  file_path: "{audit_path.as_posix()}"

tools:
  read_file:
    allow_paths:
      - "/**"
"""


def test_report_handoff_result_emits_audit_record(tmp_path):
    """The full handoff round-trip:

    1. ``Guard.run`` returns ``RuntimeOutcome::Handoff`` with a request_id.
    2. The host (this test) executes the action.
    3. The host calls ``Guard.report_handoff_result(request_id, result)``.
    4. A matching ``ExecutionFinished`` audit record lands in the JSONL log
       with ``tool == "handoff"`` and the same ``request_id``.

    This locks in the audit closure contract that S3-2 exposes to Python.
    """
    audit_path = tmp_path / "audit.jsonl"
    guard = agent_guard.Guard.from_yaml(_build_audit_policy(audit_path))

    payload = json.dumps({"path": "/workspace/README.md"})
    outcome = guard.run("read_file", payload, trust_level="trusted")
    assert outcome.outcome == "handoff", (
        f"expected handoff outcome, got {outcome.outcome!r}; "
        "Guard.run must drive the handoff path for non-mutation reads."
    )

    # Host-side execution would happen here. We then report the result.
    result = agent_guard.HandoffResult(
        exit_code=0,
        duration_ms=42,
        stdout="hello from host",
        stderr=None,
    )
    guard.report_handoff_result(outcome.request_id, result)

    # The audit writer is async-buffered. Allow a brief retry window.
    deadline_records: list[dict] = []
    for _ in range(50):  # up to ~5s (50 * 100ms)
        if audit_path.exists():
            with audit_path.open("r", encoding="utf-8") as fh:
                lines = [line.strip() for line in fh if line.strip()]
            deadline_records = [json.loads(line) for line in lines]
            if any(
                rec.get("type") == "execution_finished"
                and rec.get("tool") == "handoff"
                and rec.get("request_id") == outcome.request_id
                for rec in deadline_records
            ):
                break
        time.sleep(0.1)

    assert deadline_records, f"audit file at {audit_path} stayed empty"

    finished = [
        rec
        for rec in deadline_records
        if rec.get("type") == "execution_finished"
        and rec.get("tool") == "handoff"
        and rec.get("request_id") == outcome.request_id
    ]
    assert finished, (
        "expected an ExecutionFinished audit record with tool=handoff and "
        f"matching request_id={outcome.request_id!r}; got: {deadline_records!r}"
    )
    record = finished[0]
    assert record["sandbox_type"] == "host-handoff"
    assert record["exit_code"] == 0
    assert record["duration_ms"] == 42


def test_report_handoff_result_accepts_stderr(tmp_path):
    """Hosts may pass non-zero exit + stderr; the binding must not raise."""
    audit_path = tmp_path / "audit.jsonl"
    guard = agent_guard.Guard.from_yaml(_build_audit_policy(audit_path))

    payload = json.dumps({"path": "/workspace/README.md"})
    outcome = guard.run("read_file", payload, trust_level="trusted")
    assert outcome.outcome == "handoff"

    result = agent_guard.HandoffResult(
        exit_code=1,
        duration_ms=7,
        stdout=None,
        stderr="handoff stderr",
    )
    # Should not raise.
    guard.report_handoff_result(outcome.request_id, result)


def test_handoff_result_repr():
    r = agent_guard.HandoffResult(exit_code=0, duration_ms=10)
    text = repr(r)
    assert "HandoffResult" in text
    assert "exit_code=0" in text


# ── RuntimeDecision/Outcome predicates are mutually exclusive ────────────────


def test_runtime_decision_predicates_are_mutually_exclusive(guard):
    d = guard.decide("bash", "echo runtime", trust_level="trusted")
    flags = [d.is_execute(), d.is_handoff(), d.is_deny(), d.is_ask_for_approval()]
    assert flags.count(True) == 1, f"expected exactly one True predicate, got {flags}"


def test_runtime_outcome_predicates_are_mutually_exclusive(guard):
    outcome = guard.run("bash", "echo runtime", trust_level="trusted")
    flags = [
        outcome.is_executed(),
        outcome.is_handoff(),
        outcome.is_denied(),
        outcome.is_ask_for_approval(),
    ]
    assert flags.count(True) == 1, f"expected exactly one True predicate, got {flags}"


# ── repr smoke ────────────────────────────────────────────────────────────────


def test_runtime_decision_repr_contains_outcome(guard):
    d = guard.decide("bash", "echo runtime", trust_level="trusted")
    assert "execute" in repr(d)


def test_runtime_outcome_repr_contains_outcome_and_request_id(guard):
    outcome = guard.run("bash", "echo runtime", trust_level="trusted")
    text = repr(outcome)
    assert "executed" in text
    assert outcome.request_id in text
