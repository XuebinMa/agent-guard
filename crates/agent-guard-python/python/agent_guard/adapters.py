import asyncio
import json
import time
from typing import Any, Callable, Optional


DEFAULT_MODE = "enforce"
DEFAULT_TRUST_LEVEL = "untrusted"
MAX_PAYLOAD_BYTES = 1024 * 1024
SHELL_TOOL_NAMES = {"bash", "shell", "terminal", "sh", "zsh", "cmd", "powershell", "pwsh"}


class AgentGuardAdapterError(Exception):
    def __init__(self, message: str, *, decision: Any = None, status: Optional[str] = None,
                 policy_version: Optional[str] = None,
                 policy_verification_status: Optional[str] = None,
                 policy_verification_error: Optional[str] = None,
                 sandbox_type: Optional[str] = None, receipt: Optional[str] = None,
                 code: Optional[str] = None, matched_rule: Optional[str] = None,
                 ask_prompt: Optional[str] = None,
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
    return str(name or "").lower() in SHELL_TOOL_NAMES


def resolve_mode(tool_name: str, mode: str) -> str:
    """
    Resolve the requested adapter mode to one of "enforce", "check", or "run".

    - "enforce"  → always go through ``Guard.execute`` (sandboxed run).
    - "check"    → always go through ``Guard.check`` (policy-only, host runs original).
    - "auto"     → for shell tools, behave like "enforce"; for non-shell tools,
                   prefer ``Guard.run`` (the unified runtime API) when the binding
                   exposes it, falling back to "check" for older bindings.

    The returned token "run" is a private contract between this helper and the
    adapter dispatch path; it is only produced when the host's ``Guard`` actually
    advertises a ``run`` method, so adapters can safely call ``guard.run`` after
    seeing it.
    """
    resolved = validate_mode(mode)
    if resolved != "auto":
        return resolved
    if is_shell_tool_name(tool_name):
        return "enforce"
    # Non-shell auto: use the runtime API when available, else fall back to check.
    return "run"


def has_runtime_api(guard: Any) -> bool:
    """True iff this Guard binding exposes the unified runtime API used by mode=auto."""
    return callable(getattr(guard, "run", None))


def prepare_payload(tool_name: str, raw_input: Any) -> str:
    shell_tool = is_shell_tool_name(tool_name)
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
    outcome = getattr(decision, "outcome", "deny")
    is_ask = outcome in ("ask_user", "ask_for_approval")
    status = "ask_required" if is_ask else "denied"
    message = (
        getattr(decision, "ask_prompt", None)
        or getattr(decision, "message", None)
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

    - ``Executed`` — return the sandbox output mapped through the standard
      execute-result path. (Currently this only happens for shell-shaped
      tools, but the branch is here for robustness.)
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
            except Exception:
                # Reporting must never mask the host failure; swallow audit
                # errors and let the original exception propagate.
                pass
            raise
        duration_ms = int((time.monotonic() - start) * 1000)
        handoff_result = _build_handoff_result(
            guard,
            exit_code=0,
            duration_ms=duration_ms,
            stderr=None,
        )
        try:
            guard.report_handoff_result(request_id, handoff_result)
        except Exception:
            # Same rationale as the failure branch: audit reporting must not
            # silently corrupt a successful host execution.
            pass
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
    """Async variant of :func:`dispatch_via_run`. ``async_handler``, when set,
    is awaited on the Handoff path; otherwise ``handler`` is invoked on a
    worker thread."""
    handler_kwargs = handler_kwargs or {}

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

    if _is_handoff_outcome(outcome):
        request_id = getattr(outcome, "request_id", "")
        start = time.monotonic()
        try:
            if async_handler is not None:
                result = await async_handler(*handler_args, **handler_kwargs)
            else:
                result = await asyncio.to_thread(handler, *handler_args, **handler_kwargs)
        except BaseException as host_exc:  # noqa: BLE001
            duration_ms = int((time.monotonic() - start) * 1000)
            handoff_result = _build_handoff_result(
                guard,
                exit_code=1,
                duration_ms=duration_ms,
                stderr=str(host_exc),
            )
            try:
                guard.report_handoff_result(request_id, handoff_result)
            except Exception:
                pass
            raise
        duration_ms = int((time.monotonic() - start) * 1000)
        handoff_result = _build_handoff_result(
            guard,
            exit_code=0,
            duration_ms=duration_ms,
            stderr=None,
        )
        try:
            guard.report_handoff_result(request_id, handoff_result)
        except Exception:
            pass
        return result

    if _is_executed_outcome(outcome):
        return outcome

    if _is_denied_outcome(outcome) or _is_ask_outcome(outcome):
        raise build_security_error(outcome)

    raise AgentGuardExecutionError(
        "agent-guard run returned an unknown outcome",
        status=getattr(outcome, "outcome", None) or getattr(outcome, "status", "unknown"),
    )
