import asyncio
import json
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
                 ask_prompt: Optional[str] = None):
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
    resolved = validate_mode(mode)
    if resolved != "auto":
        return resolved
    return "enforce" if is_shell_tool_name(tool_name) else "check"


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


def build_security_error(decision: Any, *, fallback_message: Optional[str] = None) -> AgentGuardSecurityError:
    outcome = getattr(decision, "outcome", "deny")
    status = "ask_required" if outcome == "ask_user" else "denied"
    message = (
        getattr(decision, "ask_prompt", None)
        or getattr(decision, "message", None)
        or fallback_message
        or ("agent-guard requires user approval before tool execution" if status == "ask_required"
            else "agent-guard denied tool execution")
    )
    error_type = AgentGuardAskRequiredError if outcome == "ask_user" else AgentGuardDeniedError
    return error_type(
        message,
        decision=decision,
        status=status,
        policy_version=getattr(decision, "policy_version", None),
        policy_verification_status=getattr(decision, "policy_verification_status", None),
        policy_verification_error=getattr(decision, "policy_verification_error", None),
        code=getattr(decision, "code", None),
        matched_rule=getattr(decision, "matched_rule", None),
        ask_prompt=getattr(decision, "ask_prompt", None),
    )


def ensure_verified_policy_for_auto(decision: Any) -> None:
    if getattr(decision, "policy_verification_status", None) != "invalid":
        return

    synthetic_decision = type("PolicyDecision", (), {
        "outcome": "deny",
        "message": getattr(decision, "policy_verification_error", None)
        or "policy signature verification failed; auto mode refuses to continue",
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


async def run_check_async(guard: Any, *, tool: str, payload: str, guard_options: dict[str, Any]) -> Any:
    return await asyncio.to_thread(guard.check, tool=tool, payload=payload, **guard_options)


async def run_execute_async(guard: Any, *, tool: str, payload: str, guard_options: dict[str, Any]) -> Any:
    return await asyncio.to_thread(guard.execute, tool=tool, payload=payload, **guard_options)
