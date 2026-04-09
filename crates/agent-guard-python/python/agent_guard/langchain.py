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
    is_shell_tool = tool.name in ["bash", "shell", "terminal"]
    if mode == "auto":
        resolved_mode = "enforce" if is_shell_tool else "check"
    else:
        resolved_mode = mode

    def _prepare_payload(*args, **kwargs) -> str:
        """
        Ensures the payload conforms to the agent-guard SDK expectations.
        """
        raw_input = None
        if args and len(args) == 1 and not kwargs:
            raw_input = args[0]
        elif kwargs and not args:
            raw_input = kwargs
        else:
            raw_input = {"args": args, "kwargs": kwargs}

        # CWE-770: Limit payload size to 1MB
        payload_json = json.dumps(raw_input)
        if len(payload_json) > 1024 * 1024:
             raise ValueError("Tool payload too large (max 1MB)")

        if is_shell_tool:
            if isinstance(raw_input, str):
                return json.dumps({"command": raw_input})
            elif isinstance(raw_input, dict) and "command" in raw_input:
                return json.dumps(raw_input)
            else:
                return json.dumps({"command": str(raw_input)})
        
        if isinstance(raw_input, (str, bytes, int, float, bool)):
            return json.dumps({"input": raw_input})
        return payload_json

    def guarded_run(*args, **kwargs) -> Any:
        payload_str = _prepare_payload(*args, **kwargs)
        
        if resolved_mode == "enforce":
            result: ExecuteResult = guard.execute(
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
