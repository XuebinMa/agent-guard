"""
LangChain adapter tests for agent-guard.

Run with (after `maturin develop`):
    pytest crates/agent-guard-python/tests/test_langchain_adapter.py -v
"""

import json
import asyncio
import pytest
from agent_guard import (
    AgentGuardDeniedError,
    AgentGuardSecurityError,
    Guard,
    wrap_langchain_tool,
)


# ── Mock LangChain BaseTool ──────────────────────────────────────────────────

class MockBaseTool:
    """Minimal mock of langchain_core.tools.BaseTool."""
    def __init__(self, name, description=""):
        self.name = name
        self.description = description

    def _run(self, *args, **kwargs):
        raise NotImplementedError()

    async def _arun(self, *args, **kwargs):
        return self._run(*args, **kwargs)

    def run(self, tool_input, **kwargs):
        return self._run(tool_input, **kwargs)

    def invoke(self, input, config=None, **kwargs):
        return self.run(input, **kwargs)


class MockShellTool(MockBaseTool):
    def __init__(self):
        super().__init__("bash", "Executes shell commands")

    def _run(self, command: str) -> str:
        return f"ORIGINAL_SHELL: {command}"


class MockCalcTool(MockBaseTool):
    def __init__(self):
        super().__init__("calc", "Calculator")

    def _run(self, expression: str) -> str:
        return f"ORIGINAL_CALC: {expression}"


# ── Fixtures ─────────────────────────────────────────────────────────────────

POLICY_CHECK = """
version: 1
default_mode: workspace_write
tools:
  bash:
    deny:
      - "rm -rf"
    ask:
      - prefix: "git push"
  custom:
    calc: {}
"""

POLICY_BLOCKED = """
version: 1
default_mode: read_only
tools:
  custom:
    calc:
      mode: blocked
      allow: ["2+2"]
"""


@pytest.fixture
def guard():
    return Guard.from_yaml(POLICY_CHECK)


@pytest.fixture
def guard_blocked():
    return Guard.from_yaml(POLICY_BLOCKED)


# ── Category 1: Input Validation ─────────────────────────────────────────────

def test_wrap_rejects_non_tool(guard):
    """Object without _run should raise ValueError."""
    class NotATool:
        name = "fake"

    with pytest.raises(ValueError, match="missing _run"):
        wrap_langchain_tool(guard, NotATool())


def test_wrap_returns_same_instance(guard):
    """wrap_langchain_tool returns the same tool object (identity)."""
    tool = MockCalcTool()
    wrapped = wrap_langchain_tool(guard, tool, mode="check")
    assert wrapped is tool


# ── Category 2: Mode Resolution ──────────────────────────────────────────────

def test_auto_mode_non_shell_uses_check(guard):
    """Non-shell tool in auto mode should use check (original _run runs)."""
    tool = MockCalcTool()
    wrapped = wrap_langchain_tool(guard, tool, mode="auto", trust_level="trusted")
    result = wrapped.run("2+2")
    assert "ORIGINAL_CALC" in result


def test_explicit_check_on_shell_tool(guard):
    """Shell tool with explicit mode=check should run original _run logic."""
    tool = MockShellTool()
    wrapped = wrap_langchain_tool(guard, tool, mode="check", trust_level="trusted")
    result = wrapped.run("echo hello")
    assert "ORIGINAL_SHELL" in result


# ── Category 3: Check Mode ───────────────────────────────────────────────────

def test_check_mode_allow(guard):
    """Check mode with allowed input should run original logic."""
    tool = MockCalcTool()
    wrapped = wrap_langchain_tool(guard, tool, mode="check", trust_level="trusted")
    result = wrapped.run("1+1")
    assert "ORIGINAL_CALC: 1+1" == result


def test_check_mode_deny(guard):
    """Check mode with denied input should raise AgentGuardSecurityError."""
    tool = MockShellTool()
    wrapped = wrap_langchain_tool(guard, tool, mode="check", trust_level="trusted")
    with pytest.raises(AgentGuardSecurityError):
        wrapped.run("rm -rf /")


def test_check_mode_ask(guard):
    """Check mode with ask-triggering input should raise AgentGuardSecurityError."""
    tool = MockShellTool()
    wrapped = wrap_langchain_tool(guard, tool, mode="check", trust_level="trusted")
    with pytest.raises(AgentGuardSecurityError):
        wrapped.run("git push origin main")


# ── Category 4: Enforce Mode ─────────────────────────────────────────────────

def test_enforce_mode_allowed_command(guard):
    """Enforce mode with allowed command should return sandbox stdout."""
    tool = MockShellTool()
    wrapped = wrap_langchain_tool(guard, tool, mode="enforce", trust_level="trusted")
    result = wrapped.run("echo hello_from_sandbox")
    # Should come from sandbox execution, NOT the mock's _run
    assert "ORIGINAL_SHELL" not in result
    assert "hello_from_sandbox" in result


def test_enforce_mode_denied_command(guard):
    """Enforce mode with denied command should raise AgentGuardSecurityError."""
    tool = MockShellTool()
    wrapped = wrap_langchain_tool(guard, tool, mode="enforce", trust_level="trusted")
    with pytest.raises(AgentGuardSecurityError):
        wrapped.run("rm -rf /")


# ── Category 5: Payload ──────────────────────────────────────────────────────

def test_shell_payload_string_wrapping(guard):
    """Raw string input to shell tool should be wrapped and work."""
    tool = MockShellTool()
    wrapped = wrap_langchain_tool(guard, tool, mode="enforce", trust_level="trusted")
    result = wrapped.run("echo payload_test")
    assert "payload_test" in result


def test_shell_payload_dict_passthrough(guard):
    """Dict with 'command' key should pass through to shell tool."""
    tool = MockShellTool()
    wrapped = wrap_langchain_tool(guard, tool, mode="enforce", trust_level="trusted")
    result = wrapped.run({"command": "echo dict_test"})
    assert "dict_test" in result


def test_payload_size_limit(guard):
    """Payload exceeding 1MB should raise ValueError."""
    tool = MockCalcTool()
    wrapped = wrap_langchain_tool(guard, tool, mode="check", trust_level="trusted")
    huge_input = "x" * (1024 * 1024 + 1)
    with pytest.raises(ValueError, match="too large"):
        wrapped.run(huge_input)


# ── Category 6: Error Attributes ─────────────────────────────────────────────

def test_security_error_has_decision(guard):
    """AgentGuardSecurityError should have a decision attribute with message."""
    tool = MockShellTool()
    wrapped = wrap_langchain_tool(guard, tool, mode="check", trust_level="trusted")
    with pytest.raises(AgentGuardSecurityError) as exc_info:
        wrapped.run("rm -rf /")
    assert hasattr(exc_info.value, "decision")
    assert exc_info.value.decision.message is not None


# ── Category 7: Blocked Mode ─────────────────────────────────────────────────

def test_blocked_tool_deny(guard_blocked):
    """Tool in blocked mode should deny unauthorized calls."""
    tool = MockCalcTool()
    wrapped = wrap_langchain_tool(guard_blocked, tool, mode="check")
    with pytest.raises(AgentGuardSecurityError):
        wrapped.run("10/0")


def test_blocked_tool_allow(guard_blocked):
    """Tool in blocked mode should allow explicitly allowed calls."""
    tool = MockCalcTool()
    wrapped = wrap_langchain_tool(guard_blocked, tool, mode="check")
    result = wrapped.run("2+2")
    assert "ORIGINAL_CALC: 2+2" == result


# ── Category 8: Policy verification fail-closed (signed policies) ────────────

def _invalid_signed_guard():
    return Guard.from_signed_yaml(
        POLICY_CHECK,
        "0000000000000000000000000000000000000000000000000000000000000001",
        "ff" * 64,
    )


def test_auto_mode_fails_closed_for_invalid_signed_policy():
    """Auto mode must refuse to dispatch when the policy signature is invalid."""
    invalid_guard = _invalid_signed_guard()
    tool = MockCalcTool()
    wrapped = wrap_langchain_tool(invalid_guard, tool, mode="auto", trust_level="trusted")
    with pytest.raises(AgentGuardDeniedError) as exc_info:
        wrapped.run("2+2")
    assert exc_info.value.code == "PolicyVerificationFailed"


def test_check_mode_fails_closed_for_invalid_signed_policy():
    """Check mode must also refuse to dispatch when the policy signature is invalid."""
    invalid_guard = _invalid_signed_guard()
    tool = MockCalcTool()
    wrapped = wrap_langchain_tool(invalid_guard, tool, mode="check", trust_level="trusted")
    with pytest.raises(AgentGuardDeniedError) as exc_info:
        wrapped.run("2+2")
    assert exc_info.value.code == "PolicyVerificationFailed"


def test_check_mode_async_fails_closed_for_invalid_signed_policy():
    """Async check path must refuse to dispatch when the policy signature is invalid."""
    invalid_guard = _invalid_signed_guard()
    tool = MockCalcTool()
    wrapped = wrap_langchain_tool(invalid_guard, tool, mode="check", trust_level="trusted")
    with pytest.raises(AgentGuardDeniedError) as exc_info:
        asyncio.run(wrapped._arun("2+2"))
    assert exc_info.value.code == "PolicyVerificationFailed"


# ── Category 9: Handoff path through Guard.run (S3-2 runtime API) ────────────
#
# These tests use a hand-rolled FakeGuard that quacks like the future PyO3
# binding (run / report_handoff_result + outcome objects). They validate the
# adapter contract independently of S3-2's binding changes — once S3-2 lands,
# the same behaviour must hold against the real binding.


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
    """Mimics enough of Guard to drive the run/report_handoff_result path."""

    def __init__(self, outcome):
        self._outcome = outcome
        self.run_calls = []
        self.handoff_reports = []

    def run(self, *, tool, payload, **kwargs):
        self.run_calls.append({"tool": tool, "payload": payload, **kwargs})
        return self._outcome

    def report_handoff_result(self, request_id, result):
        self.handoff_reports.append((request_id, result))

    # Stubs so wrap_langchain_tool's static type hint (Guard) is satisfied at runtime.
    def check(self, *args, **kwargs):
        raise AssertionError("check() must not be called on the run path")

    def execute(self, *args, **kwargs):
        raise AssertionError("execute() must not be called on the run path")


def test_auto_mode_handoff_invokes_original_and_closes_audit_loop():
    """Non-shell auto mode must take the run() path, call the original tool on
    Handoff, and report the result back via report_handoff_result()."""
    fake = FakeGuard(_FakeOutcome("handoff", request_id="req-handoff-42"))
    tool = MockCalcTool()
    wrapped = wrap_langchain_tool(fake, tool, mode="auto", trust_level="trusted")

    result = wrapped.run("2+2")

    assert "ORIGINAL_CALC: 2+2" == result
    assert len(fake.run_calls) == 1
    assert fake.run_calls[0]["tool"] == "calc"
    assert len(fake.handoff_reports) == 1
    request_id, handoff_result = fake.handoff_reports[0]
    assert request_id == "req-handoff-42"
    assert handoff_result.exit_code == 0
    assert handoff_result.duration_ms >= 0
    assert handoff_result.stderr is None


def test_auto_mode_handoff_handler_raise_still_reports_audit():
    """If the host handler raises on the Handoff path, the adapter must still
    emit report_handoff_result(exit_code=1) BEFORE re-raising."""
    fake = FakeGuard(_FakeOutcome("handoff", request_id="req-handoff-err"))

    class RaisingTool(MockBaseTool):
        def __init__(self):
            super().__init__("calc", "raises")

        def _run(self, *args, **kwargs):
            raise RuntimeError("boom")

    tool = RaisingTool()
    wrapped = wrap_langchain_tool(fake, tool, mode="auto", trust_level="trusted")

    with pytest.raises(RuntimeError, match="boom"):
        wrapped.run("ignored")

    assert len(fake.handoff_reports) == 1
    request_id, handoff_result = fake.handoff_reports[0]
    assert request_id == "req-handoff-err"
    assert handoff_result.exit_code == 1
    assert handoff_result.stderr == "boom"


def test_auto_mode_run_deny_raises_security_error_without_handler_call():
    """A Denied outcome from run() must raise AgentGuardDeniedError and NOT
    call the original tool."""
    fake = FakeGuard(
        _FakeOutcome(
            "denied",
            request_id="req-deny",
            message="blocked by policy",
            code="DeniedByRule",
            matched_rule="block-everything",
        )
    )

    class TrackingTool(MockBaseTool):
        def __init__(self):
            super().__init__("calc", "tracking")
            self.calls = 0

        def _run(self, *args, **kwargs):
            self.calls += 1
            return "should-not-run"

    tool = TrackingTool()
    wrapped = wrap_langchain_tool(fake, tool, mode="auto", trust_level="trusted")

    with pytest.raises(AgentGuardDeniedError) as exc_info:
        wrapped.run("anything")

    assert exc_info.value.code == "DeniedByRule"
    assert exc_info.value.matched_rule == "block-everything"
    assert tool.calls == 0
    assert fake.handoff_reports == []


def test_auto_mode_async_handoff_uses_original_arun_when_present():
    """The async dispatch path on Handoff must prefer _arun and still close
    the audit loop."""
    fake = FakeGuard(_FakeOutcome("handoff", request_id="req-async-handoff"))

    class AsyncCalc(MockBaseTool):
        def __init__(self):
            super().__init__("calc", "async")
            self.async_called = False

        def _run(self, expression: str) -> str:
            return f"SYNC_CALC: {expression}"

        async def _arun(self, expression: str) -> str:
            self.async_called = True
            return f"ASYNC_CALC: {expression}"

    tool = AsyncCalc()
    wrapped = wrap_langchain_tool(fake, tool, mode="auto", trust_level="trusted")

    result = asyncio.run(wrapped._arun("3*3"))

    assert result == "ASYNC_CALC: 3*3"
    assert tool.async_called is True
    assert len(fake.handoff_reports) == 1
    request_id, handoff_result = fake.handoff_reports[0]
    assert request_id == "req-async-handoff"
    assert handoff_result.exit_code == 0
