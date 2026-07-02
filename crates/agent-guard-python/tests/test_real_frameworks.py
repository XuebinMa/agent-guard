"""
Real-framework adapter tests (issue #101).

These exercise ``wrap_langchain_tool`` against the REAL
``langchain_core.tools.BaseTool`` — not the mocks in
``test_langchain_adapter.py`` — so CI can matrix over framework versions.

When ``langchain-core`` is not installed (the default ``verify.sh python``
venv), the whole module skips. The CI ``python-framework-test`` job installs a
matrixed framework version (via ``AGENT_GUARD_PY_FRAMEWORKS``) and runs it for
real. This file supersedes the manual ``real_runtime_validation.py`` script.
"""

import pytest

langchain_core = pytest.importorskip(
    "langchain_core", reason="real-framework tests require langchain-core"
)

from typing import Type  # noqa: E402

from langchain_core.tools import BaseTool  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from agent_guard import (  # noqa: E402
    AgentGuardSecurityError,
    Guard,
    wrap_langchain_tool,
)

# ── Real LangChain tool implementations ──────────────────────────────────────


class ShellInput(BaseModel):
    command: str = Field(description="The shell command to execute")


class RealShellTool(BaseTool):
    name: str = "bash"
    description: str = "Executes shell commands"
    args_schema: Type[BaseModel] = ShellInput

    def _run(self, command: str) -> str:
        # In enforce mode the sandbox owns execution; this marker must never
        # appear in an enforce-mode result.
        return f"ORIGINAL_SHELL: {command}"

    async def _arun(self, command: str) -> str:
        return self._run(command)


class CalcInput(BaseModel):
    expression: str = Field(description="The math expression to evaluate")


class RealCalcTool(BaseTool):
    name: str = "calc"
    description: str = "Performs math"
    args_schema: Type[BaseModel] = CalcInput

    def _run(self, expression: str) -> str:
        # In check mode this runs only after policy authorization.
        return f"ORIGINAL_CALC: {expression}"

    async def _arun(self, expression: str) -> str:
        return self._run(expression)


# ── Fixtures ─────────────────────────────────────────────────────────────────

ENFORCE_POLICY = """
version: 1
default_mode: workspace_write
tools:
  bash:
    allow:
      - prefix: "echo"
"""

BLOCKED_CALC_POLICY = """
version: 1
default_mode: read_only
tools:
  custom:
    calc:
      mode: blocked
      allow: ["2+2"]
"""


@pytest.fixture(scope="module")
def enforce_guard():
    return Guard.from_yaml(ENFORCE_POLICY)


@pytest.fixture(scope="module")
def calc_guard():
    return Guard.from_yaml(BLOCKED_CALC_POLICY)


# ── Enforce mode: the sandbox owns execution ─────────────────────────────────


def test_enforce_run_executes_in_sandbox_not_original(enforce_guard):
    tool = wrap_langchain_tool(enforce_guard, RealShellTool(), mode="enforce")
    result = tool.run("echo real-framework-run")
    assert "real-framework-run" in result
    assert "ORIGINAL_SHELL" not in result, "original tool logic must be bypassed"


def test_enforce_invoke_lcel_path(enforce_guard):
    # `invoke` is the LCEL-era entry point; the wrapper must secure it too.
    tool = wrap_langchain_tool(enforce_guard, RealShellTool(), mode="enforce")
    result = tool.invoke({"command": "echo real-framework-invoke"})
    assert "real-framework-invoke" in result
    assert "ORIGINAL_SHELL" not in result


# ── Check mode: policy gate in front of the original tool ────────────────────


def test_check_authorized_call_runs_original_logic(calc_guard):
    tool = wrap_langchain_tool(calc_guard, RealCalcTool(), mode="check")
    result = tool.run("2+2")
    assert "ORIGINAL_CALC" in result, "authorized call must reach the original tool"
    assert "2+2" in result


def test_check_unauthorized_call_is_blocked(calc_guard):
    tool = wrap_langchain_tool(calc_guard, RealCalcTool(), mode="check")
    with pytest.raises(AgentGuardSecurityError) as exc_info:
        tool.run("10/0")
    assert exc_info.value.decision.code == "BlockedByMode"


def test_framework_version_is_reported():
    # Surfaces the matrixed framework version in the pytest output so a CI
    # failure names the exact langchain-core release it happened against.
    version = getattr(langchain_core, "__version__", "unknown")
    print(f"langchain-core version under test: {version}")
    assert version
