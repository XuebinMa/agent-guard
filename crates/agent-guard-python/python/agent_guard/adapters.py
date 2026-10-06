import asyncio
import inspect
import json
import logging
import time
from typing import Any, Callable, Optional


DEFAULT_MODE = "enforce"
DEFAULT_TRUST_LEVEL = "untrusted"
MAX_PAYLOAD_BYTES = 1024 * 1024
SHELL_PAYLOAD_TOOL_NAMES = {"bash", "shell", "terminal"}
OWNED_SHELL_TOOL_NAMES = {"bash"}
SHELL_LIKE_TOOL_NAMES = {
    "bash",
    "bash.exe",
    "shell",
    "terminal",
    "sh",
    "sh.exe",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
}
LOGGER = logging.getLogger(__name__)


class AgentGuardAdapterError(Exception):
    def __init__(self, message: str, *, decision: Any = None, status: Optional[str] = None,
                 policy_version: Optional[str] = None,
                 policy_verification_status: Optional[str] = None,
                 policy_verification_error: Optional[str] = None,
                 sandbox_type: Optional[str] = None, receipt: Optional[str] = None,
                 code: Optional[str] = None, matched_rule: Optional[str] = None,
                 ask_prompt: Optional[str] = None,
                 host_action_completed: bool = False,
                 host_result: Any = None,
                 request_id: Optional[str] = None,
                 handoff_result: Any = None,
                 cause: Optional[BaseException] = None):
        super().__init__(message)
        self.decision = decision
        self.status = status
        self.policy_version = policy_version
        self.policy_verification_status = policy_verification_status
        self.policy_verification_error = policy_verification_error
        self.sandbox_type = sandbox_type
        self.receipt = receipt
        self.code = code
        self.matched_rule = matched_rule
        self.ask_prompt = ask_prompt
        self.host_action_completed = host_action_completed
        self.host_result = host_result
        self.request_id = request_id
        self.handoff_result = handoff_result
        self.cause = cause


class AgentGuardSecurityError(AgentGuardAdapterError):
    pass


class AgentGuardDeniedError(AgentGuardSecurityError):
    pass


class AgentGuardAskRequiredError(AgentGuardSecurityError):
    pass


class AgentGuardExecutionError(AgentGuardAdapterError):
    pass


def validate_mode(mode: str) -> str:
    resolved = mode or DEFAULT_MODE
    if resolved not in {"check", "enforce", "auto"}:
        raise AgentGuardExecutionError(f"Unsupported adapter mode {resolved!r}", status="error")
    return resolved


def is_shell_tool_name(name: str) -> bool:
    return str(name or "") in OWNED_SHELL_TOOL_NAMES


def resolve_mode(tool_name: str, mode: str) -> str:
    """
    Resolve the requested adapter mode to one of "enforce", "check", or "run".

    - "enforce"  → always go through ``Guard.execute`` (sandboxed run).
    - "check"    → always go through ``Guard.check`` (policy-only, host runs original).
    - "auto"     → for the exact built-in tool ID ``bash``, behave like
                   "enforce"; for every other tool ID, prefer ``Guard.run`` (the
                   unified runtime API) when the binding exposes it, falling
                   back to "check" for older bindings.

    The returned token "run" is a private contract between this helper and the
    adapter dispatch path. The wrapper must still call :func:`has_runtime_api`
    and fall back to ``check`` for an older binding.
    """
    resolved = validate_mode(mode)
    if resolved != "auto":
        return resolved
    if is_shell_tool_name(tool_name):
        return "enforce"
    normalized_tool = str(tool_name or "").lower()
    if normalized_tool in SHELL_LIKE_TOOL_NAMES:
        raise AgentGuardExecutionError(
            f"Auto mode refuses shell-like custom tool ID {tool_name!r}; "
            "map a real Bash-backed tool to the exact ID 'bash' or choose "
            "an explicit mode",
            status="configuration_error",
            code="UnsupportedShellAlias",
        )
    # Non-shell auto: use the runtime API when available, else fall back to check.
    return "run"


def has_runtime_api(guard: Any) -> bool:
    """True iff this Guard binding exposes the unified runtime API used by mode=auto."""
    return callable(getattr(guard, "run", None)) and callable(
        getattr(guard, "report_handoff_result", None)
    )


def prepare_payload(tool_name: str, raw_input: Any) -> str:
    shell_tool = str(tool_name or "") in SHELL_PAYLOAD_TOOL_NAMES
    if shell_tool:
        if isinstance(raw_input, str):
            payload = {"command": raw_input}
        elif isinstance(raw_input, dict) and "command" in raw_input:
            payload = raw_input
        else:
            payload = {"command": str(raw_input)}
    elif isinstance(raw_input, (str, bytes, int, float, bool)):
        payload = {"input": raw_input}
    else:
        payload = raw_input

    payload_json = json.dumps(payload)
    if len(payload_json.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise ValueError("Tool payload too large (max 1MB)")
    return payload_json


# ── Unified error-attribute extraction ───────────────────────────────────────
#
# All four error sites — Decision objects from check(), decisions embedded in
# ExecuteResult, RuntimeOutcome objects from run(), and synthetic policy-
# verification decisions — now flow through a single attribute extractor so
# the surfaced AgentGuardSecurityError / AgentGuardExecutionError instances
# carry identical fields regardless of which Guard API produced them.


def _decision_to_error_attrs(decision: Any) -> dict:
    """Pull the canonical error-shaping attributes off a Decision-like object.

    Works for: Decision (from Guard.check), decisions embedded in ExecuteResult,
    RuntimeOutcome variants from Guard.run, and the synthetic decision built in
    ``ensure_verified_policy``. Any of these may be missing fields; we always
    produce the full attribute set with ``None`` for absent values.

    For ``RuntimeOutcome`` shapes, ``code`` / ``matched_rule`` / ``ask_prompt``
    live on the embedded ``decision`` child rather than the outcome itself, so
    we look there first and fall back to the outer object for legacy shapes.
    """
    inner = getattr(decision, "decision", None)
    code_source = inner if inner is not None else decision
    return {
        "policy_version": getattr(decision, "policy_version", None),
        "policy_verification_status": getattr(decision, "policy_verification_status", None),
        "policy_verification_error": getattr(decision, "policy_verification_error", None),
        "code": getattr(code_source, "code", None),
        "matched_rule": getattr(code_source, "matched_rule", None),
        "ask_prompt": getattr(code_source, "ask_prompt", None),
    }


def build_security_error(decision: Any, *, fallback_message: Optional[str] = None) -> AgentGuardSecurityError:
    inner = getattr(decision, "decision", None)
    message_source = inner if inner is not None else decision
    outcome = getattr(message_source, "outcome", None) or getattr(
        decision, "outcome", "deny"
    )
    is_ask = outcome in ("ask_user", "ask_for_approval")
    status = "ask_required" if is_ask else "denied"
    message = (
        getattr(message_source, "ask_prompt", None)
        or getattr(message_source, "message", None)
        or fallback_message
        or ("agent-guard requires user approval before tool execution" if is_ask
            else "agent-guard denied tool execution")
    )
    error_type = AgentGuardAskRequiredError if is_ask else AgentGuardDeniedError
    return error_type(
        message,
        decision=decision,
        status=status,
        **_decision_to_error_attrs(decision),
    )


def ensure_verified_policy(decision: Any) -> None:
    if getattr(decision, "policy_verification_status", None) != "invalid":
        return

    synthetic_decision = type("PolicyDecision", (), {
        "outcome": "deny",
        "message": getattr(decision, "policy_verification_error", None)
        or "agent-guard refuses to continue with an invalid policy signature",
        "code": "PolicyVerificationFailed",
        "matched_rule": None,
        "ask_prompt": None,
        "policy_version": getattr(decision, "policy_version", None),
        "policy_verification_status": getattr(decision, "policy_verification_status", None),
        "policy_verification_error": getattr(decision, "policy_verification_error", None),
    })()
    raise build_security_error(synthetic_decision)


def handle_execute_result(result: Any, *, result_mapper: Optional[Callable[[Any, Any], Any]], original_input: Any) -> Any:
    if result.status == "executed":
        if callable(result_mapper):
            return result_mapper(result, original_input)
        return result

    if result.decision is not None:
        raise build_security_error(result.decision)

    raise AgentGuardExecutionError(
        "agent-guard returned an unknown execution status",
        status=result.status,
        policy_version=getattr(result, "policy_version", None),
        policy_verification_status=getattr(result, "policy_verification_status", None),
        policy_verification_error=getattr(result, "policy_verification_error", None),
        sandbox_type=getattr(result, "sandbox_type", None),
        receipt=getattr(result, "receipt", None),
    )


# ── Runtime-API dispatch (Guard.run) ─────────────────────────────────────────


def _is_handoff_outcome(outcome: Any) -> bool:
    name = getattr(outcome, "outcome", None) or getattr(outcome, "status", None)
    return name == "handoff"


def _is_executed_outcome(outcome: Any) -> bool:
    name = getattr(outcome, "outcome", None) or getattr(outcome, "status", None)
    return name in ("executed", "execute")


def _is_denied_outcome(outcome: Any) -> bool:
    name = getattr(outcome, "outcome", None) or getattr(outcome, "status", None)
    return name in ("denied", "deny")


def _is_ask_outcome(outcome: Any) -> bool:
    name = getattr(outcome, "outcome", None) or getattr(outcome, "status", None)
    return name in ("ask_for_approval", "ask_user", "ask_required")


def _build_handoff_result(guard: Any, *, exit_code: int, duration_ms: int,
                          stderr: Optional[str] = None) -> Any:
    """Construct a ``HandoffResult`` value the binding accepts.

    Prefer the binding's exported ``HandoffResult`` class when present; fall
    back to a duck-typed object so tests with mock guards remain decoupled
    from the PyO3 layout.
    """
    try:
        from . import HandoffResult as _HandoffResult  # type: ignore
        return _HandoffResult(exit_code=exit_code, duration_ms=duration_ms, stderr=stderr)
    except Exception:
        return type("HandoffResult", (), {
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "stderr": stderr,
        })()


def _surface_report_failure_on_host_error(
    host_error: BaseException, report_error: Exception
) -> None:
    """Preserve the host exception while making the audit failure observable."""
    message = f"agent-guard could not record the handoff result: {report_error}"
    try:
        setattr(host_error, "agent_guard_report_error", report_error)
    except Exception:  # pragma: no cover - unusual immutable exception types
        pass
    add_note = getattr(host_error, "add_note", None)
    if callable(add_note):
        add_note(message)
    LOGGER.error(message, exc_info=report_error)


def _raise_success_report_failure(
    report_error: Exception,
    host_result: Any,
    outcome: Any,
    request_id: str,
    handoff_result: Any,
) -> None:
    """A completed host action is not a successful guarded lifecycle if its
    terminal report was rejected."""
    raise AgentGuardExecutionError(
        "host action already completed but agent-guard could not record its "
        f"handoff result; do not retry automatically: {report_error}",
        status="report_failed_after_execution",
        code="HandoffReportFailedAfterExecution",
        host_action_completed=True,
        host_result=host_result,
        request_id=request_id,
        handoff_result=handoff_result,
        policy_version=getattr(outcome, "policy_version", None),
        policy_verification_status=getattr(
            outcome, "policy_verification_status", None
        ),
        policy_verification_error=getattr(
            outcome, "policy_verification_error", None
        ),
        cause=report_error,
    ) from report_error


async def _complete_async_handoff(guard, outcome, request_id, started, action):
    """Report an awaitable's actual completion, including its host exception."""
    try:
        result = await action()
    except BaseException as host_exc:
        handoff_result = _build_handoff_result(
            guard,
            exit_code=1,
            duration_ms=int((time.monotonic() - started) * 1000),
            stderr=str(host_exc),
        )
        try:
            await asyncio.to_thread(
                guard.report_handoff_result, request_id, handoff_result
            )
        except Exception as report_error:
            _surface_report_failure_on_host_error(host_exc, report_error)
        raise
    handoff_result = _build_handoff_result(
        guard,
        exit_code=0,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    try:
        await asyncio.to_thread(
            guard.report_handoff_result, request_id, handoff_result
        )
    except Exception as report_error:
        _raise_success_report_failure(
            report_error, result, outcome, request_id, handoff_result
        )
    return result


def dispatch_via_run(
    guard: Any,
    *,
    tool: str,
    payload: str,
    guard_options: dict,
    handler: Callable[..., Any],
    handler_args: tuple = (),
    handler_kwargs: Optional[dict] = None,
) -> Any:
    """
    Drive an ``auto``-mode (non-shell) tool through the unified ``Guard.run``
    API and close the audit loop on Handoff.

    Behaviour by ``RuntimeOutcome`` variant:

    - ``Executed`` — return the Guard-owned runtime outcome without invoking
      the host handler (for example, WriteFile or a mutating HTTP request).
    - ``Handoff``  — invoke ``handler`` to actually perform the action, time
      it, and report the outcome back via ``Guard.report_handoff_result``
      (exit_code 0 on clean return, 1 if the handler raised). The host
      exception, if any, is re-raised AFTER the audit record is emitted so
      the audit loop closes either way.
    - ``Denied`` / ``AskForApproval`` — raise the appropriate
      ``AgentGuardSecurityError`` subclass via ``build_security_error``.
    """
    handler_kwargs = handler_kwargs or {}
    try:
        outcome = guard.run(tool=tool, payload=payload, **guard_options)
    except Exception as exc:
        raise AgentGuardExecutionError(
            f"agent-guard run failed: {exc}",
            status="error",
            cause=exc,
        ) from exc

    ensure_verified_policy(outcome)

    if _is_handoff_outcome(outcome):
        request_id = getattr(outcome, "request_id", "")
        start = time.monotonic()
        try:
            result = handler(*handler_args, **handler_kwargs)
        except BaseException as host_exc:  # noqa: BLE001 — propagate after audit
            duration_ms = int((time.monotonic() - start) * 1000)
            handoff_result = _build_handoff_result(
                guard,
                exit_code=1,
                duration_ms=duration_ms,
                stderr=str(host_exc),
            )
            try:
                guard.report_handoff_result(request_id, handoff_result)
            except Exception as report_error:
                # The host failure remains primary, but the audit failure must
                # remain visible on that exception and in host logs.
                _surface_report_failure_on_host_error(host_exc, report_error)
            raise
        if inspect.isawaitable(result):
            return _complete_async_handoff(
                guard, outcome, request_id, start, lambda: result
            )
        duration_ms = int((time.monotonic() - start) * 1000)
        handoff_result = _build_handoff_result(
            guard,
            exit_code=0,
            duration_ms=duration_ms,
            stderr=None,
        )
        try:
            guard.report_handoff_result(request_id, handoff_result)
        except Exception as report_error:
            _raise_success_report_failure(
                report_error, result, outcome, request_id, handoff_result
            )
        return result

    if _is_executed_outcome(outcome):
        # Outcome carries an embedded sandbox output; return it raw — non-shell
        # auto callers don't supply a result_mapper here, so the host receives
        # the runtime outcome and can introspect output.stdout itself.
        return outcome

    if _is_denied_outcome(outcome) or _is_ask_outcome(outcome):
        raise build_security_error(outcome)

    raise AgentGuardExecutionError(
        "agent-guard run returned an unknown outcome",
        status=getattr(outcome, "outcome", None) or getattr(outcome, "status", "unknown"),
    )


async def run_check_async(guard: Any, *, tool: str, payload: str, guard_options: dict[str, Any]) -> Any:
    return await asyncio.to_thread(guard.check, tool=tool, payload=payload, **guard_options)


async def run_execute_async(guard: Any, *, tool: str, payload: str, guard_options: dict[str, Any]) -> Any:
    return await asyncio.to_thread(guard.execute, tool=tool, payload=payload, **guard_options)


async def dispatch_via_run_async(
    guard: Any,
    *,
    tool: str,
    payload: str,
    guard_options: dict,
    handler: Callable[..., Any],
    handler_args: tuple = (),
    handler_kwargs: Optional[dict] = None,
    async_handler: Optional[Callable[..., Any]] = None,
) -> Any:
    """Async handoff dispatch. A synchronous handler's entire lifecycle runs
    on one worker, so cancellation of the waiter cannot prematurely consume
    its handoff. The worker reports its actual result when it finishes."""
    handler_kwargs = handler_kwargs or {}
    if async_handler is None:
        result = await asyncio.to_thread(
            dispatch_via_run,
            guard,
            tool=tool,
            payload=payload,
            guard_options=guard_options,
            handler=handler,
            handler_args=handler_args,
            handler_kwargs=handler_kwargs,
        )
        return await result if inspect.isawaitable(result) else result

    try:
        outcome = await asyncio.to_thread(
            guard.run, tool=tool, payload=payload, **guard_options
        )
    except Exception as exc:
        raise AgentGuardExecutionError(
            f"agent-guard run failed: {exc}",
            status="error",
            cause=exc,
        ) from exc

    ensure_verified_policy(outcome)

    if _is_handoff_outcome(outcome):
        request_id = getattr(outcome, "request_id", "")
        start = time.monotonic()
        return await _complete_async_handoff(
            guard, outcome, request_id, start,
            lambda: async_handler(*handler_args, **handler_kwargs),
        )

    if _is_executed_outcome(outcome):
        return outcome

    if _is_denied_outcome(outcome) or _is_ask_outcome(outcome):
        raise build_security_error(outcome)

    raise AgentGuardExecutionError(
        "agent-guard run returned an unknown outcome",
        status=getattr(outcome, "outcome", None) or getattr(outcome, "status", "unknown"),
    )
