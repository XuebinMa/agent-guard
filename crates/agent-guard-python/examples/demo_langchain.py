import sys
import os
import asyncio

# To run this demo locally before installing:
# export PYTHONPATH=$PYTHONPATH:$(pwd)/python
# Build the shared library first: maturin develop

try:
    from agent_guard import Guard, wrap_langchain_tool, AgentGuardSecurityError
except ImportError:
    print("Error: agent-guard not found in path.")
    print("Usage: 1. Build: 'maturin develop' inside crates/agent-guard-python")
    print("       2. Run: 'python examples/demo_langchain.py'")
    sys.exit(1)

# ── Mock LangChain BaseTool ──────────────────────────────────────────────────
# This mimics the core structure of langchain_core.tools.BaseTool

class BaseTool:
    """Simulated LangChain BaseTool interface."""
    def __init__(self, name, description):
        self.name = name
        self.description = description

    def _run(self, *args, **kwargs):
        raise NotImplementedError()

    async def _arun(self, *args, **kwargs):
        return self._run(*args, **kwargs)

    def run(self, tool_input, **kwargs):
        return self._run(tool_input, **kwargs)

    def invoke(self, input, config=None, **kwargs):
        # High-level entry point used in LCEL
        return self.run(input, **kwargs)

class ShellTool(BaseTool):
    def __init__(self):
        super().__init__("bash", "Executes shell commands")
        
    def _run(self, command: str) -> str:
        # In ENFORCE mode, this original logic is bypassed by the sandbox
        print(f"   [Original Logic] This should NOT be visible in enforce mode: {command}")
        return f"Logic output of {command}"

class CalculationTool(BaseTool):
    def __init__(self):
        super().__init__("calc", "Performs math")
        
    def _run(self, expression: str) -> str:
        # In CHECK mode, this logic runs ONLY if agent-guard allows it
        print(f"   [Original Logic] Calculating: {expression}")
        return f"Result: {eval(expression)}"

# ── Demo Logic ───────────────────────────────────────────────────────────────

async def main():
    print("🛡️ agent-guard Python Demo: Credible LangChain Prototype")
    print("========================================================\n")

    # 1. Initialize Guard with Policy
    policy = """
version: 1
default_mode: read_only
tools:
  bash: { deny: ["rm -rf"] }
  calc: { allow: ["1+1"] }
    """
    guard = Guard.from_yaml(policy)
    print("✅ Guard initialized.\n")

    # 2. Wrap Tools with Explicit Modes
    # Shell tools are perfect for 'enforce' (Sandbox replaces logic)
    shell_tool = wrap_langchain_tool(guard, ShellTool(), mode="enforce")
    
    # Generic tools use 'check' (Guard authorizes, original logic runs)
    calc_tool = wrap_langchain_tool(guard, CalculationTool(), mode="check")

    print(f"✅ 'bash' secured in ENFORCE mode (Sandbox isolation).")
    print(f"✅ 'calc' secured in CHECK mode (Policy gatekeeper).\n")

    # 3. Scenario: Payload Normalization Check
    print("👉 Scenario 1: Payload Normalization (ls -l)")
    # Input is raw string 'ls -l', adapter wraps it into {"command": "ls -l"} for SDK
    output = shell_tool.run("ls -l")
    print(f"   Result: {output} (Note: Original logic bypassed)\n")

    # 4. Scenario: Authorization Mode (Safe Call)
    print("👉 Scenario 2: Authorization Mode (1+1)")
    output = calc_tool.run("1+1")
    print(f"   Result: {output} (Note: Original logic executed safely)\n")

    # 5. Scenario: Attack Interception
    print("👉 Scenario 3: Intercepting 'rm -rf /'")
    try:
        shell_tool.invoke("rm -rf /")
    except AgentGuardSecurityError as e:
        print(f"🔒 [INTERCEPTED] Access denied: {e.decision.message}")
        print(f"   Decision Hash: {e.decision.policy_version[:8]}...\n")

    print("========================================================")
    print("Prototype validation finished. Payload contract verified.")

if __name__ == "__main__":
    asyncio.run(main())
