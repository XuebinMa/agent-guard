# agent-guard-python

> **Python Security Execution Runtime for AI Agents.**

This package provides Python bindings for `agent-guard`, enabling you to intercept, validate, and isolate tool calls in frameworks like LangChain and OpenAI Agents.

---

## 🚀 Quick Start (Python Adapters)

> **Status**: The Python wrapper layer is now a **beta adapter surface** with official LangChain and OpenAI-style handler wrappers. Node remains the most mature integration path in the repository, but Python no longer stops at a single prototype wrapper.

Integrate `agent-guard` into your existing LangChain tools in just 3 lines of code:

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

- 🛡️ **OS-Level Isolation**: Seamless access to Linux Seccomp, Windows Low-IL, and macOS Seatbelt sandboxes.
- 📜 **Signed Receipts**: Optional cryptographic proof of execution (requires signing key).
- 🔏 **Signed Policy Loading**: Optional detached-signature verification for `policy.yaml`.
- 🔒 **Deny Fuse**: Automatically locks agents that repeatedly violate security rules.
- 📊 **Real-time Auditing**: Forensic JSONL logs and metrics integration.
- ⚠️ **Typed Adapter Errors**: Distinct deny, ask-required, and execution failure exceptions.

---

## 🔧 Installation

```bash
# Via Git (v0.2.0-rc1)
pip install git+https://github.com/XuebinMa/agent-guard.git#subdirectory=crates/agent-guard-python
```

*Note: Requires Rust toolchain for building from source.*

---

## 📺 Demos

Check the `examples/` directory for full usage scenarios:
- `demo_langchain.py`: Comprehensive 3-line integration demo.
- `provenance_receipt.py`: Cryptographic verification example.
