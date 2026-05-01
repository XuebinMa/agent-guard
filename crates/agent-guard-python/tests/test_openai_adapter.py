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
