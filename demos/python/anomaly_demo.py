"""
agent-guard anomaly detection demo
==================================
Demonstrates frequency-based anomaly detection.

Run:
    python demos/python/anomaly_demo.py
"""

import json
import agent_guard

# Initialize tracing to see security warnings
agent_guard.init_tracing()

POLICY = """
version: 1
default_mode: workspace_write
audit:
  enabled: true
  output: stdout
"""

guard = agent_guard.Guard.from_yaml(POLICY)

print("=== agent-guard Anomaly Detection Demo ===")
print("Default limit: 30 calls per minute per actor.")

def call_tool(actor: str):
    return guard.check(
        "bash", 
        json.dumps({"command": "ls"}), 
        actor=actor
    )

print("\nSimulating 35 rapid-fire tool calls for actor 'attacker'...")

for i in range(1, 36):
    d = call_tool("attacker")
    if not d.is_allow():
        print(f"\n[BLOCKED] Call {i} was blocked!")
        print(f"Outcome: {d.outcome.upper()}")
        print(f"Code: {d.code}")
        print(f"Message: {d.message}")
        break
    if i % 10 == 0:
        print(f"Call {i} allowed...")

print("\nVerifying that another actor 'normal_user' is NOT blocked...")
d = call_tool("normal_user")
print(f"Outcome for 'normal_user': {d.outcome.upper()}")

print("\nDone.")
