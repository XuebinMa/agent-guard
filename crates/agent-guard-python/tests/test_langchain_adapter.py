"""
LangChain adapter tests for agent-guard.

Run with (after `maturin develop`):
    pytest crates/agent-guard-python/tests/test_langchain_adapter.py -v
"""

import json
import asyncio
import threading
import pytest
from agent_guard import (
    AgentGuardAskRequiredError,
    AgentGuardDeniedError,
    AgentGuardExecutionError,
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

def test_auto_mode_non_shell_uses_runtime_handoff(guard):
    """Current bindings route a non-shell auto call through run/handoff."""
    tool = MockCalcTool()
    wrapped = wrap_langchain_tool(guard, tool, mode="auto", trust_level="trusted")
    result = wrapped.run("2+2")
    assert "ORIGINAL_CALC" in result


def test_auto_mode_falls_back_when_binding_cannot_report_handoff():
    class RunOnlyLegacyGuard:
        def check(self, **_kwargs):
            return type("Decision", (), {"outcome": "allow"})()

        def execute(self, **_kwargs):
            raise AssertionError("execute must not run for a non-shell tool")

        def run(self, **_kwargs):
            raise AssertionError("run without a reporting API must not be used")

    tool = MockCalcTool()
    wrapped = wrap_langchain_tool(
        RunOnlyLegacyGuard(), tool, mode="auto", trust_level="trusted"
    )

    assert wrapped.run("2+2") == "ORIGINAL_CALC: 2+2"


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
        message = kwargs.get("message", None)
        code = kwargs.get("code", None)
        matched_rule = kwargs.get("matched_rule", None)
        ask_prompt = kwargs.get("ask_prompt", None)
        self.decision = None
        if outcome in ("denied", "deny", "ask_for_approval", "ask_user"):
            self.decision = type(
                "RuntimeDecision",
                (),
                {
                    "outcome": outcome,
                    "message": message,
                    "code": code,
                    "matched_rule": matched_rule,
                    "ask_prompt": ask_prompt,
                },
            )()


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


class ReportingFailsGuard(FakeGuard):
    def report_handoff_result(self, request_id, result):
        super().report_handoff_result(request_id, result)
        raise RuntimeError("handoff report failed")


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


@pytest.mark.parametrize(
    "tool_name",
    ["shell", "terminal", "BASH", "sh", "zsh", "cmd", "powershell", "pwsh"],
)
def test_auto_mode_requires_exact_bash_tool_id(tool_name):
    """Only the exact built-in ID ``bash`` belongs to Guard-owned execution.
    Shell-shaped aliases must not silently widen into host handoff."""
    fake = FakeGuard(
        _FakeOutcome("handoff", request_id=f"req-custom-alias-{tool_name}")
    )

    class AliasTool(MockBaseTool):
        def __init__(self):
            super().__init__(tool_name, "custom shell-shaped alias")

        def _run(self, command: str) -> str:
            return f"HOST_ALIAS: {command}"

    with pytest.raises(AgentGuardExecutionError, match="exact ID 'bash'") as caught:
        wrap_langchain_tool(fake, AliasTool(), mode="auto", trust_level="trusted")
    assert caught.value.code == "UnsupportedShellAlias"
    assert fake.run_calls == []
    assert fake.handoff_reports == []


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


def test_auto_mode_handoff_report_failure_rejects_apparent_success():
    fake = ReportingFailsGuard(
        _FakeOutcome(
            "handoff",
            request_id="req-report-error",
            policy_version="policy-report-error",
            policy_verification_status="unsigned",
        )
    )
    tool = MockCalcTool()
    wrapped = wrap_langchain_tool(fake, tool, mode="auto", trust_level="trusted")

    with pytest.raises(
        AgentGuardExecutionError,
        match="host action already completed but agent-guard could not record",
    ) as caught:
        wrapped.run("2+2")
    assert isinstance(caught.value.cause, RuntimeError)
    assert caught.value.host_action_completed is True
    assert caught.value.host_result == "ORIGINAL_CALC: 2+2"
    assert caught.value.code == "HandoffReportFailedAfterExecution"
    assert caught.value.request_id == "req-report-error"
    assert caught.value.handoff_result.exit_code == 0
    assert caught.value.policy_version == "policy-report-error"
    assert caught.value.policy_verification_status == "unsigned"
    assert caught.value.policy_verification_error is None
    assert len(fake.handoff_reports) == 1


def test_auto_mode_handoff_report_failure_preserves_handler_error():
    fake = ReportingFailsGuard(_FakeOutcome("handoff", request_id="req-both-errors"))

    class RaisingTool(MockBaseTool):
        def __init__(self):
            super().__init__("calc", "raises")

        def _run(self, *args, **kwargs):
            raise RuntimeError("original handler error")

    wrapped = wrap_langchain_tool(
        fake, RaisingTool(), mode="auto", trust_level="trusted"
    )

    with pytest.raises(RuntimeError, match="original handler error") as caught:
        wrapped.run("ignored")
    assert isinstance(caught.value.agent_guard_report_error, RuntimeError)
    if hasattr(caught.value, "__notes__"):
        assert any(
            "could not record the handoff result" in note
            for note in caught.value.__notes__
        )
    assert len(fake.handoff_reports) == 1


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
    assert str(exc_info.value) == "blocked by policy"
    assert tool.calls == 0
    assert fake.handoff_reports == []


def test_auto_mode_rejects_invalid_runtime_handoff_without_handler_call():
    fake = FakeGuard(
        _FakeOutcome(
            "handoff",
            request_id="req-invalid-runtime-handoff",
            policy_version="policy-invalid-runtime",
            policy_verification_status="invalid",
            policy_verification_error="signature verification failed",
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

    with pytest.raises(AgentGuardDeniedError) as caught:
        wrapped.run("anything")

    assert caught.value.code == "PolicyVerificationFailed"
    assert caught.value.policy_version == "policy-invalid-runtime"
    assert caught.value.policy_verification_status == "invalid"
    assert tool.calls == 0
    assert fake.handoff_reports == []


def test_auto_mode_run_ask_preserves_nested_approval_prompt():
    fake = FakeGuard(
        _FakeOutcome(
            "ask_for_approval",
            request_id="req-ask",
            message="approval required",
            code="AskRequired",
            ask_prompt="Approve calculator call?",
        )
    )
    tool = MockCalcTool()
    wrapped = wrap_langchain_tool(fake, tool, mode="auto", trust_level="trusted")

    with pytest.raises(AgentGuardAskRequiredError) as caught:
        wrapped.run("2+2")

    assert str(caught.value) == "Approve calculator call?"
    assert caught.value.ask_prompt == "Approve calculator call?"
    assert caught.value.code == "AskRequired"
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


def test_auto_mode_async_handoff_reports_off_event_loop_thread():
    event_loop_thread = threading.get_ident()

    class ThreadRecordingGuard(FakeGuard):
        def __init__(self, outcome):
            super().__init__(outcome)
            self.report_thread = None

        def report_handoff_result(self, request_id, result):
            self.report_thread = threading.get_ident()
            super().report_handoff_result(request_id, result)

    fake = ThreadRecordingGuard(
        _FakeOutcome("handoff", request_id="req-async-report-thread")
    )

    class DirectAsyncCalc(MockBaseTool):
        def __init__(self):
            super().__init__("calc", "async thread probe")

        async def _arun(self, expression: str) -> str:
            return f"ASYNC_CALC: {expression}"

    wrapped = wrap_langchain_tool(
        fake, DirectAsyncCalc(), mode="auto", trust_level="trusted"
    )

    assert asyncio.run(wrapped._arun("4*4")) == "ASYNC_CALC: 4*4"
    assert fake.report_thread is not None
    assert fake.report_thread != event_loop_thread


def test_auto_mode_async_report_failure_rejects_apparent_success():
    fake = ReportingFailsGuard(
        _FakeOutcome("handoff", request_id="req-async-report-error")
    )

    class AsyncCalc(MockBaseTool):
        def __init__(self):
            super().__init__("calc", "async")

        async def _arun(self, expression: str) -> str:
            return f"ASYNC_CALC: {expression}"

    wrapped = wrap_langchain_tool(
        fake, AsyncCalc(), mode="auto", trust_level="trusted"
    )

    with pytest.raises(
        AgentGuardExecutionError,
        match="host action already completed but agent-guard could not record",
    ) as caught:
        asyncio.run(wrapped._arun("3*3"))
    assert isinstance(caught.value.cause, RuntimeError)
    assert caught.value.host_action_completed is True
    assert caught.value.host_result == "ASYNC_CALC: 3*3"


def test_auto_mode_async_report_failure_preserves_handler_error():
    fake = ReportingFailsGuard(
        _FakeOutcome("handoff", request_id="req-async-both-errors")
    )

    class AsyncFailure(MockBaseTool):
        def __init__(self):
            super().__init__("calc", "async failure")

        async def _arun(self, _expression: str) -> str:
            raise RuntimeError("original async handler error")

    wrapped = wrap_langchain_tool(
        fake, AsyncFailure(), mode="auto", trust_level="trusted"
    )

    with pytest.raises(RuntimeError, match="original async handler error") as caught:
        asyncio.run(wrapped._arun("ignored"))
    assert isinstance(caught.value.agent_guard_report_error, RuntimeError)
