from typing import Any, Callable, Optional

from ._agent_guard import Guard
from .adapters import (
    build_security_error,
    ensure_verified_policy_for_auto,
    handle_execute_result,
    prepare_payload,
    resolve_mode,
)


def wrap_openai_tool(
    guard: Guard,
    handler: Callable[[Any], Any],
    *,
    tool: str,
    mode: str = "check",
    trust_level: str = "untrusted",
    agent_id: Optional[str] = None,
    actor: Optional[str] = None,
    result_mapper: Optional[Callable[[Any, Any], Any]] = None,
    payload_mapper: Optional[Callable[[Any], str]] = None,
):
    """
    Wrap an OpenAI-style tool handler with agent-guard checks.

    The wrapped callable accepts the original handler input and either:
    - forwards to the original handler in `check` / `auto` mode when allowed
    - executes in the sandbox in `enforce` mode
    - raises a typed security exception on deny / ask-required
    """
    if not callable(handler):
        raise TypeError("wrap_openai_tool requires a callable handler")

    resolved_mode = resolve_mode(tool, mode)
    guard_options = {
        "agent_id": agent_id,
        "actor": actor,
        "trust_level": trust_level,
    }

    def wrapped(input_data: Any, *args, **kwargs):
        payload = payload_mapper(input_data) if callable(payload_mapper) else prepare_payload(tool, input_data)

        if resolved_mode == "enforce":
            result = guard.execute(tool=tool, payload=payload, **guard_options)
            return handle_execute_result(
                result,
                result_mapper=result_mapper,
                original_input=input_data,
            )

        decision = guard.check(tool=tool, payload=payload, **guard_options)
        if decision.outcome != "allow":
            raise build_security_error(decision)
        if mode == "auto":
            ensure_verified_policy_for_auto(decision)
        return handler(input_data, *args, **kwargs)

    return wrapped
