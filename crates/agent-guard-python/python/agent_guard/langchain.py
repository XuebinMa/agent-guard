import json
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
    trust_level: str = "untrusted"
) -> Any:
    """
    Wraps a LangChain tool with agent-guard security enforcement.
    
    Args:
        guard: The initialized agent-guard.Guard instance.
        tool: A LangChain tool instance (BaseTool).
        agent_id: Optional ID for the agent.
        actor: Optional ID for the human actor.
        trust_level: Trust level for the execution ("untrusted", "trusted", "admin").
        
    Returns:
        The same tool instance with a guarded _run method.
    """
    if not hasattr(tool, "_run"):
        raise ValueError("Provided object does not look like a LangChain BaseTool (missing _run).")

    original_run = tool._run
    
    def guarded_run(*args, **kwargs) -> Any:
        # 1. Construct payload
        if args and not kwargs and len(args) == 1:
            payload_data = args[0]
        else:
            payload_data = {**kwargs}
            if args:
                payload_data["args"] = args
            
        payload_str = json.dumps(payload_data) if not isinstance(payload_data, (str, bytes)) else payload_data
        
        # 2. Secure Execute
        # We use the tool's 'name' as the tool identifier in agent-guard policy.
        result: ExecuteResult = guard.execute(
            tool=tool.name,
            payload=payload_str,
            agent_id=agent_id,
            actor=actor,
            trust_level=trust_level
        )
        
        if result.status == "executed":
            # If the sandbox actually ran something (e.g. bash), return that output.
            if result.output:
                return result.output.stdout
            
            # If it's a 'noop' sandbox or custom tool, we might need to run the original logic.
            # But in agent-guard design, 'execute' IS the execution. 
            # If the tool is just a wrapper for a local function, the sandbox MUST handle it.
            return "Execution successful (Output captured by sandbox)."
            
        elif result.status == "denied":
            raise AgentGuardSecurityError(result.decision)
        elif result.status == "ask_required":
            # Handle user intervention
            raise AgentGuardSecurityError(result.decision) # Fallback to deny if no UI
            
        return "Unknown security status."

    # Apply the patch
    tool._run = guarded_run
    
    # Handle async if present
    if hasattr(tool, "_arun"):
        original_arun = tool._arun
        async def guarded_arun(*args, **kwargs) -> Any:
            # For now, we reuse the synchronous check logic as a placeholder
            # A real production version would use an async-compatible execute if available.
            return guarded_run(*args, **kwargs)
        tool._arun = guarded_arun
    
    return tool
