import json
import asyncio
from typing import Any, Dict, Optional, List, Union, Callable
from ._agent_guard import Guard, ExecuteResult

class AgentGuardSecurityError(Exception):
    """Raised when agent-guard denies an execution."""
    def __init__(self, decision_data):
        self.decision = decision_data
        msg = f"Security Deny: {decision_data.message or 'Policy violation'}"
        if decision_data.matched_rule:
            msg += f" (Rule: {decision_data.matched_rule})"
        super().__init__(msg)

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
    
    # Resolve mode
    if mode == "auto":
        resolved_mode = "enforce" if tool.name in ["bash", "shell", "terminal"] else "check"
    else:
        resolved_mode = mode

    def _prepare_payload(*args, **kwargs) -> str:
        if args and not kwargs and len(args) == 1:
            payload_data = args[0]
        else:
            payload_data = {**kwargs}
            if args:
                payload_data["args"] = args
        return json.dumps(payload_data) if not isinstance(payload_data, (str, bytes)) else payload_data

    def guarded_run(*args, **kwargs) -> Any:
        payload_str = _prepare_payload(*args, **kwargs)
        
        if resolved_mode == "enforce":
            # Tier 2: Sandbox Enforcement (Direct Execution)
            result: ExecuteResult = guard.execute(
                tool=tool.name,
                payload=payload_str,
                agent_id=agent_id,
                actor=actor,
                trust_level=trust_level
            )
            
            if result.status == "executed":
                return result.output.stdout if result.output else ""
            elif result.status == "denied":
                raise AgentGuardSecurityError(result.decision)
            elif result.status == "ask_required":
                raise AgentGuardSecurityError(result.decision)
        else:
            # Tier 1: Policy Check only (Wrap original logic)
            decision = guard.check(
                tool=tool.name,
                payload=payload_str,
                agent_id=agent_id,
                actor=actor,
                trust_level=trust_level
            )
            
            if decision.outcome == "allow":
                return original_run(*args, **kwargs)
            else:
                raise AgentGuardSecurityError(decision)

    async def guarded_arun(*args, **kwargs) -> Any:
        payload_str = _prepare_payload(*args, **kwargs)
        
        if resolved_mode == "enforce":
            # Run blocking rust execution in a thread to remain async-friendly
            result = await asyncio.to_thread(
                guard.execute,
                tool=tool.name,
                payload=payload_str,
                agent_id=agent_id,
                actor=actor,
                trust_level=trust_level
            )
            if result.status == "executed":
                return result.output.stdout if result.output else ""
            else:
                raise AgentGuardSecurityError(result.decision)
        else:
            decision = await asyncio.to_thread(
                guard.check,
                tool=tool.name,
                payload=payload_str,
                agent_id=agent_id,
                actor=actor,
                trust_level=trust_level
            )
            
            if decision.outcome == "allow":
                if original_arun:
                    return await original_arun(*args, **kwargs)
                return await asyncio.to_thread(original_run, *args, **kwargs)
            else:
                raise AgentGuardSecurityError(decision)

    # Patch the tool
    tool._run = guarded_run
    if original_arun or hasattr(tool, "_arun"):
        tool._arun = guarded_arun
    
    # Also override high-level invoke if it exists (LangChain LCEL)
    if hasattr(tool, "invoke"):
        original_invoke = tool.invoke
        def guarded_invoke(input, config=None, **kwargs):
            # This ensures even LCEL path is guarded
            return tool.run(input, **kwargs)
        tool.invoke = guarded_invoke

    return tool
