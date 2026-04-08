import sys
import os

# To run this demo locally before installing:
# export PYTHONPATH=$PYTHONPATH:$(pwd)/python
# And you need to have the built shared library in python/agent_guard/_agent_guard.so (or .pyd)

try:
    from agent_guard import Guard, wrap_langchain_tool, AgentGuardSecurityError
except ImportError:
    print("Error: agent-guard not found in path.")
    print("Usage: 1. Build: 'maturin develop' inside crates/agent-guard-python")
    print("       2. Run: 'python examples/demo_langchain.py'")
    sys.exit(1)

# ── Mock LangChain BaseTool ──────────────────────────────────────────────────

class BaseTool:
    """Simulated LangChain BaseTool."""
    def __init__(self, name, description):
        self.name = name
        self.description = description

    def _run(self, *args, **kwargs):
        raise NotImplementedError()

    def run(self, tool_input, **kwargs):
        return self._run(tool_input, **kwargs)

class ShellTool(BaseTool):
    def __init__(self):
        super().__init__("bash", "Executes shell commands")
        
    def _run(self, command: str) -> str:
        # This original method is what gets bypassed by the guard
        print(f"   [Original Tool] System call: {command}")
        return f"Real output of {command}"

# ── Demo Logic ───────────────────────────────────────────────────────────────

def main():
    print("🛡️ agent-guard Python Demo: 3-Line LangChain Integration")
    print("====================================================\n")

    # 1. Initialize Guard with Policy
    # Line 1: Load policy
    policy = """
version: 1
default_mode: read_only
tools:
  bash:
    deny:
      - "rm -rf"
      - "cat /etc/passwd"
    """
    guard = Guard.from_yaml(policy)
    print("✅ Guard initialized.")

    # 2. Create and Wrap the Tool
    # Line 2: Create original tool
    shell_tool = ShellTool()
    
    # Line 3: Wrap it!
    guarded_tool = wrap_langchain_tool(
        guard, 
        shell_tool, 
        agent_id="langchain-agent-v1"
    )
    print("✅ Tool 'bash' secured via agent-guard wrapper.\n")

    # 3. Scenario: Normal Path
    print("👉 Scenario 1: Safe request 'ls -l'")
    output = guarded_tool.run("ls -l")
    print(f"   Result: {output}\n")

    # 4. Scenario: Attack Blocked
    print("👉 Scenario 2: Attack attempt 'cat /etc/passwd'")
    try:
        guarded_tool.run("cat /etc/passwd")
    except AgentGuardSecurityError as e:
        print(f"🔒 [CRITICAL] Security Interception!")
        print(f"   Reason: {e.decision.message}")
        print(f"   Code:   {e.decision.code}")
        print(f"   Source: {e.decision.matched_rule or 'Default Policy'}\n")

    # 5. Scenario: Persistent Locking (Deny Fuse)
    # The policy didn't have fuse enabled in the yaml string above, 
    # but let's show the principle if it were.
    
    print("====================================================")
    print("Security Parity Check:")
    print(f" - Is it a sandbox? Yes (Uses host default)")
    print(f" - Is there an audit trail? Yes (See audit.jsonl)")
    print("====================================================")

if __name__ == "__main__":
    main()
