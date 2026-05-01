import pytest

from agent_guard import (
    AgentGuardDeniedError,
    AgentGuardExecutionError,
    Guard,
    wrap_openai_tool,
)


POLICY = """
version: 1
default_mode: workspace_write
tools:
  bash:
    allow:
      - prefix: "echo"
    ask:
      - prefix: "git push"
  custom:
    web_search: {}
"""


@pytest.fixture
def guard():
    return Guard.from_yaml(POLICY)


def test_openai_wrapper_check_mode_calls_original_handler(guard):
    calls = []

    wrapped = wrap_openai_tool(
        guard,
        lambda input_data: calls.append(input_data) or {"ok": True, "query": input_data["query"]},
        tool="web_search",
        mode="check",
        trust_level="trusted",
    )

    result = wrapped({"query": "agent-guard"})
    assert result == {"ok": True, "query": "agent-guard"}
    assert calls == [{"query": "agent-guard"}]


def test_openai_wrapper_enforce_mode_returns_sandbox_output(guard):
    wrapped = wrap_openai_tool(
        guard,
        lambda _input_data: {"unused": True},
        tool="bash",
        mode="enforce",
        trust_level="trusted",
        result_mapper=lambda outcome, _input_data: outcome.output.stdout.strip(),
    )

    result = wrapped({"command": "echo python-openai"})
    assert result == "python-openai"


def test_openai_wrapper_auto_mode_fails_closed_for_invalid_signed_policy():
    invalid_guard = Guard.from_signed_yaml(
        POLICY,
        "0000000000000000000000000000000000000000000000000000000000000001",
        "ff" * 64,
    )

    wrapped = wrap_openai_tool(
        invalid_guard,
        lambda _input_data: "should-not-run",
        tool="bash",
        mode="auto",
        trust_level="trusted",
    )

    with pytest.raises(AgentGuardDeniedError) as exc_info:
        wrapped({"command": "echo blocked"})
    assert exc_info.value.code == "PolicyVerificationFailed"


def test_openai_wrapper_check_mode_fails_closed_for_invalid_signed_policy():
    invalid_guard = Guard.from_signed_yaml(
        POLICY,
        "0000000000000000000000000000000000000000000000000000000000000001",
        "ff" * 64,
    )

    handler_calls = []

    wrapped = wrap_openai_tool(
        invalid_guard,
        lambda input_data: handler_calls.append(input_data) or "should-not-run",
        tool="web_search",
        mode="check",
        trust_level="trusted",
    )

    with pytest.raises(AgentGuardDeniedError) as exc_info:
        wrapped({"query": "agent-guard"})
    assert exc_info.value.code == "PolicyVerificationFailed"
    assert handler_calls == []


def test_openai_wrapper_rejects_invalid_mode(guard):
    with pytest.raises(AgentGuardExecutionError, match="Unsupported adapter mode"):
        wrap_openai_tool(guard, lambda _input_data: None, tool="web_search", mode="invalid")


# ── Handoff path through Guard.run (S3-2 runtime API) ────────────────────────
#
# As with the LangChain tests, these use a duck-typed FakeGuard so the contract
# is exercised independently of S3-2's binding work.


class _FakeOutcome:
    def __init__(self, outcome, **kwargs):
        self.outcome = outcome
        self.request_id = kwargs.get("request_id", "req-1")
        self.policy_version = kwargs.get("policy_version", "v1")
        self.policy_verification_status = kwargs.get("policy_verification_status", "unsigned")
        self.policy_verification_error = kwargs.get("policy_verification_error", None)
        self.message = kwargs.get("message", None)
        self.code = kwargs.get("code", None)
        self.matched_rule = kwargs.get("matched_rule", None)
        self.ask_prompt = kwargs.get("ask_prompt", None)


class FakeGuard:
    def __init__(self, outcome):
        self._outcome = outcome
        self.run_calls = []
        self.handoff_reports = []

    def run(self, *, tool, payload, **kwargs):
        self.run_calls.append({"tool": tool, "payload": payload, **kwargs})
        return self._outcome

    def report_handoff_result(self, request_id, result):
        self.handoff_reports.append((request_id, result))

    def check(self, *a, **k):
        raise AssertionError("check() must not be called on the run path")

    def execute(self, *a, **k):
        raise AssertionError("execute() must not be called on the run path")


def test_openai_auto_mode_handoff_invokes_handler_and_reports_audit():
    fake = FakeGuard(_FakeOutcome("handoff", request_id="req-openai-handoff"))
    handler_calls = []

    def handler(input_data):
        handler_calls.append(input_data)
        return {"ok": True, "echo": input_data["query"]}

    wrapped = wrap_openai_tool(
        fake,
        handler,
        tool="web_search",
        mode="auto",
        trust_level="trusted",
    )

    result = wrapped({"query": "agent-guard"})

    assert result == {"ok": True, "echo": "agent-guard"}
    assert handler_calls == [{"query": "agent-guard"}]
    assert len(fake.handoff_reports) == 1
    request_id, handoff_result = fake.handoff_reports[0]
    assert request_id == "req-openai-handoff"
    assert handoff_result.exit_code == 0


def test_openai_auto_mode_handoff_handler_raise_still_reports_audit():
    fake = FakeGuard(_FakeOutcome("handoff", request_id="req-openai-err"))

    def handler(_input_data):
        raise ValueError("oops")

    wrapped = wrap_openai_tool(
        fake,
        handler,
        tool="web_search",
        mode="auto",
        trust_level="trusted",
    )

    with pytest.raises(ValueError, match="oops"):
        wrapped({"query": "x"})

    assert len(fake.handoff_reports) == 1
    request_id, handoff_result = fake.handoff_reports[0]
    assert request_id == "req-openai-err"
    assert handoff_result.exit_code == 1
    assert handoff_result.stderr == "oops"


def test_openai_auto_mode_run_deny_raises_without_handler_call():
    fake = FakeGuard(
        _FakeOutcome(
            "denied",
            request_id="req-openai-deny",
            message="nope",
            code="DeniedByRule",
            matched_rule="rule-x",
        )
    )

    handler_calls = []

    def handler(input_data):
        handler_calls.append(input_data)
        return "should-not-run"

    wrapped = wrap_openai_tool(
        fake,
        handler,
        tool="web_search",
        mode="auto",
        trust_level="trusted",
    )

    with pytest.raises(AgentGuardDeniedError) as exc_info:
        wrapped({"query": "y"})

    assert exc_info.value.code == "DeniedByRule"
    assert exc_info.value.matched_rule == "rule-x"
    assert handler_calls == []
    assert fake.handoff_reports == []
