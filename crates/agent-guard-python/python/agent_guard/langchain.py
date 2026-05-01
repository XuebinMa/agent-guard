import asyncio
from typing import Any, Optional
from ._agent_guard import Guard
from .adapters import (
    AgentGuardSecurityError,
    build_security_error,
    ensure_verified_policy,
    handle_execute_result,
    prepare_payload,
    resolve_mode,
    run_check_async,
    run_execute_async,
)

def wrap_langchain_tool(
    guard: Guard, 
    tool: Any, 
    agent_id: Optional[str] = None,
    actor: Optional[str] = None,
    trust_level: str = "untrusted",
    mode: str = "auto"
) -> Any:
    """
    Wraps a LangChain tool with agent-guard security enforcement.
    
    Args:
        guard: The initialized agent-guard.Guard instance.
        tool: A LangChain tool instance (BaseTool).
        agent_id: Optional ID for the agent.
        actor: Optional ID for the human actor.
        trust_level: Trust level for the execution ("untrusted", "trusted", "admin").
        mode: "enforce" (sandbox), "check" (policy-only), or "auto" (enforce for shell, check for others).
        
    Returns:
        The same tool instance with guarded methods.
    """
    if not hasattr(tool, "_run"):
        raise ValueError("Provided object does not look like a LangChain BaseTool (missing _run).")

    original_run = tool._run
    original_arun = getattr(tool, "_arun", None)
    resolved_mode = resolve_mode(tool.name, mode)

    def _raw_input(*args, **kwargs) -> Any:
        if args and len(args) == 1 and not kwargs:
            return args[0]
        if kwargs and not args:
            return kwargs
        return {"args": args, "kwargs": kwargs}

    guard_options = {
        "agent_id": agent_id,
        "actor": actor,
        "trust_level": trust_level,
    }

    def guarded_run(*args, **kwargs) -> Any:
        raw_input = _raw_input(*args, **kwargs)
        payload_str = prepare_payload(tool.name, raw_input)

        if resolved_mode == "enforce":
            result = guard.execute(tool=tool.name, payload=payload_str, **guard_options)
            return handle_execute_result(
                result,
                result_mapper=lambda outcome, _original: outcome.output.stdout if outcome.output else "",
                original_input=raw_input,
            )

        decision = guard.check(tool=tool.name, payload=payload_str, **guard_options)
        if decision.outcome != "allow":
            raise build_security_error(decision)
        ensure_verified_policy(decision)
        return original_run(*args, **kwargs)

    async def guarded_arun(*args, **kwargs) -> Any:
        raw_input = _raw_input(*args, **kwargs)
        payload_str = prepare_payload(tool.name, raw_input)

        if resolved_mode == "enforce":
            result = await run_execute_async(
                guard,
                tool=tool.name,
                payload=payload_str,
                guard_options=guard_options,
            )
            return handle_execute_result(
                result,
                result_mapper=lambda outcome, _original: outcome.output.stdout if outcome.output else "",
                original_input=raw_input,
            )

        decision = await run_check_async(
            guard,
            tool=tool.name,
            payload=payload_str,
            guard_options=guard_options,
        )
        if decision.outcome != "allow":
            raise build_security_error(decision)
        ensure_verified_policy(decision)
        if original_arun:
            return await original_arun(*args, **kwargs)
        return await asyncio.to_thread(original_run, *args, **kwargs)

    # Patch the tool internals.
    try:
        tool.__dict__["_run"] = guarded_run
        if original_arun or hasattr(tool, "_arun"):
            tool.__dict__["_arun"] = guarded_arun
    except (AttributeError, TypeError):
        tool._run = guarded_run
        if original_arun or hasattr(tool, "_arun"):
            tool._arun = guarded_arun

    return tool
