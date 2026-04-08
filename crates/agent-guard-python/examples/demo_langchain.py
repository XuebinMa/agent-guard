import sys
import os
import asyncio

# Setup local paths for demo
try:
    from agent_guard import Guard, wrap_langchain_tool, AgentGuardSecurityError
except ImportError:
    print("Error: agent-guard not found.")
    sys.exit(1)

# ── Mock LangChain BaseTool ──────────────────────────────────────────────────

class BaseTool:
    """Simulated LangChain BaseTool."""
    def __init__(self, name, description):
        self.name = name
        self.description = description

    def _run(self, *args, **kwargs):
        raise NotImplementedError()

    async def _arun(self, *args, **kwargs):
        # Default async implementation calling sync
        return self._run(*args, **kwargs)

    def run(self, tool_input, **kwargs):
        return self._run(tool_input, **kwargs)

    def invoke(self, input, config=None, **kwargs):
        return self.run(input, **kwargs)

class ShellTool(BaseTool):
    def __init__(self):
        super().__init__("bash", "Executes shell commands")
        
    def _run(self, command: str) -> str:
        print(f"   [Original Tool] System call: {command}")
        return f"Real output of {command}"

class SearchTool(BaseTool):
    def __init__(self):
        super().__init__("search", "Search the web")
        
    def _run(self, query: str) -> str:
        print(f"   [Original Tool] Searching: {query}")
        return f"Results for {query}"

# ── Demo Logic ───────────────────────────────────────────────────────────────

async def main():
    print("🛡️ agent-guard Python Demo: Production-Grade LangChain Integration")
    print("================================================================\n")

    # 1. Initialize Guard
    policy = """
version: 1
default_mode: read_only
tools:
  bash: { deny: ["rm -rf"] }
  search: { allow: ["*"] }
    """
    guard = Guard.from_yaml(policy)
    print("✅ Guard initialized.\n")

    # 2. Wrap Tools with Different Modes
    shell_tool = wrap_langchain_tool(guard, ShellTool(), mode="enforce")
    search_tool = wrap_langchain_tool(guard, SearchTool(), mode="check")
    
    print(f"✅ 'bash' wrapped in ENFORCE mode (Sandbox protection).")
    print(f"✅ 'search' wrapped in CHECK mode (Policy authorization).\n")

    # 3. Scenario: Enforced Sandbox Execution
    print("👉 Scenario 1: 'bash' tool (Enforced Sandbox)")
    output = shell_tool.run("ls -l")
    print(f"   Result: {output} (Note: No 'Original Tool' print - sandbox took over)\n")

    # 4. Scenario: Policy-Only Authorization
    print("👉 Scenario 2: 'search' tool (Policy Authorization)")
    output = search_tool.run("rust security")
    print(f"   Result: {output} (Note: 'Original Tool' ran because policy allowed it)\n")

    # 5. Scenario: Async Path
    print("👉 Scenario 3: Async Execution")
    output = await shell_tool._arun("echo async_test")
    print(f"   Result: {output}\n")

    # 6. Scenario: High-level Entry (Invoke)
    print("👉 Scenario 4: LCEL Invoke path")
    try:
        shell_tool.invoke("rm -rf /")
    except AgentGuardSecurityError as e:
        print(f"🔒 [CRITICAL] Blocked by agent-guard!")
        print(f"   Reason: {e.decision.message}\n")

    print("================================================================")
    print("Demo finished. Multiple integration paths verified.")

if __name__ == "__main__":
    asyncio.run(main())
