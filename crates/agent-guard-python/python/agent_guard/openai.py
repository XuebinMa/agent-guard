from typing import Any, Callable, Optional

from ._agent_guard import Guard
from .adapters import (
    build_security_error,
    dispatch_via_run,
    ensure_verified_policy,
    handle_execute_result,
    has_runtime_api,
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

    The wrapped callable accepts the original handler input and dispatches
    according to ``mode``:

    - ``"enforce"`` — always sandbox the call via ``Guard.execute``.
    - ``"check"``   — always go through ``Guard.check`` (policy-only). The
      original handler runs in-process when allowed. Fail-closed on invalid
      policy signatures.
    - ``"auto"`` — for shell-like tools, behave like ``enforce``. For non-shell
      tools, dispatch through the unified ``Guard.run`` runtime API when the
      binding exposes it. The ``RuntimeOutcome::Handoff`` variant means the
      handler runs in-process and the adapter then calls
      ``Guard.report_handoff_result`` to close the audit loop. When the binding
      does not expose ``run`` (older builds), ``auto`` for non-shell tools
      degrades to ``check`` semantics.
    """
    if not callable(handler):
        raise TypeError("wrap_openai_tool requires a callable handler")

    resolved_mode = resolve_mode(tool, mode)

    if resolved_mode == "run" and not has_runtime_api(guard):
        resolved_mode = "check"

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

        if resolved_mode == "run":
            return dispatch_via_run(
                guard,
                tool=tool,
                payload=payload,
                guard_options=guard_options,
                handler=handler,
                handler_args=(input_data, *args),
                handler_kwargs=kwargs,
            )

        decision = guard.check(tool=tool, payload=payload, **guard_options)
        if decision.outcome != "allow":
            raise build_security_error(decision)
        ensure_verified_policy(decision)
        return handler(input_data, *args, **kwargs)

    return wrapped
