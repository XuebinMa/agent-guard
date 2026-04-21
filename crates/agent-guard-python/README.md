# agent-guard-python

> **Python bindings for execution control at the agent side-effect boundary.**

This package provides Python bindings for `agent-guard`, giving Python hosts a pre-execution decision layer before agent tool calls turn into shell commands or other side effects.

---

## 🚀 Quick Start (Python Adapters)

> **Status**: The Python wrapper layer is a **beta adapter surface**. The clearest current proof point is still shell-first execution control, and Node remains the most mature integration path in the repository.

Integrate `agent-guard` into your existing LangChain tools with a policy gate in front of the original tool:

```python
from agent_guard import Guard, wrap_langchain_tool

# 1. Initialize the Guard with your security policy
guard = Guard.from_yaml_file("policy.yaml")

# 2. Secure your existing tools
bash_tool = ShellTool() # Your original tool
secured_tool = wrap_langchain_tool(guard, bash_tool, agent_id="researcher")

# 3. Use the tool as normal - agent-guard handles the rest!
secured_tool.run("ls -la")
```

OpenAI-style handler wrapping is also available:

```python
from agent_guard import Guard, wrap_openai_tool, AgentGuardDeniedError

guard = Guard.from_yaml_file("policy.yaml")

guarded_handler = wrap_openai_tool(
    guard,
    lambda input_data: {"ok": True, "query": input_data["query"]},
    tool="web_search",
    mode="check",
    trust_level="trusted",
)

try:
    print(guarded_handler({"query": "agent-guard"}))
except AgentGuardDeniedError as error:
    print("blocked", error.code)
```

---

## ✨ Features

- 🛡️ **Pre-execution policy decisions**: Put allow/deny/ask checks in front of Python tool handlers.
- 💻 **Shell-first execution control**: The strongest current execution path is still shell / Bash style tooling.
- ⚠️ **Typed adapter errors**: Distinct deny, ask-required, and execution failure exceptions.
- 📜 **Signed receipts**: Optional cryptographic proof of execution when you need deeper verification.
- 🔏 **Signed policy loading**: Optional detached-signature verification for `policy.yaml`.
- 📊 **Auditing support**: JSONL logs and metrics integration for operator-visible outcomes.

Current boundary note:

- non-shell tools are most often a `check`-style policy gate first
- shell-style execution remains the clearest current enforcement proof point
- Python is an active adapter surface, but still below the current Node path in maturity
- `Guard.execute()` currently uses the SDK default sandbox selection internally; the Python binding does not yet expose an explicit sandbox-selection API
- if the default sandbox diagnosis falls back to `NoopSandbox`, the policy gate still runs, but OS-level isolation is not equivalent

---

## 🔧 Installation

```bash
# Via Git (v0.2.0-rc1)
pip install git+https://github.com/XuebinMa/agent-guard.git#subdirectory=crates/agent-guard-python
```

*Note: Requires Rust toolchain for building from source.*

For local development in this repository:

```bash
cd crates/agent-guard-python
maturin develop --features extension-module
pytest tests -v
```

---

## 📺 Demos

Check the `examples/` directory for full usage scenarios:
- `demo_langchain.py`: Comprehensive 3-line integration demo.
- `provenance_receipt.py`: Cryptographic verification example.
