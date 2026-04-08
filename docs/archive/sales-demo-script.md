# 💼 agent-guard Sales Demo Script

> Target Audience: CISO, CTO, Security Architects, Compliance Officers  
> Goal: Demonstrate the quantitative reduction in risk and the qualitative increase in trust provided by `agent-guard`.

---

## 🎭 Introduction (The Hook)
**Speaker**: "Most AI Agent frameworks today rely on 'System Prompts' or basic 'Allow Lists' for security. But as we've seen with recent Prompt Injection research, these LLM-level barriers are brittle. If the Agent's logic is subverted, the host system is defenseless."

---

## 🛑 Scenario 1: The Broken Baseline (Demo 1 - No Guard)
**Action**: Run `cargo run --example demo_comparison` (Focus on Tier 0 output)

**Key Narrative**:
- "Without an external security layer, an compromised Agent can successfully overwrite `/etc/authorized_keys` or wipe critical data."
- "There is no forensic trail. You only see the wreckage after the breach."
- **Quantitative Point**: "Risk Level: **CRITICAL**. 100% of subverted commands execute successfully."

---

## 🛡️ Scenario 2: Defense in Depth (Demo 2 - agent-guard Hard Blocking)
**Action**: Run `cargo run --example demo_comparison` (Focus on Tier 2 output)

**Key Narrative**:
- "With `agent-guard`, we don't just ask the Agent to be good. We enforce it at two levels."
- "**Level 1 (Policy Engine)**: Our restricted DSL immediately blocks known dangerous patterns."
- "**Level 2 (OS Sandbox)**: Even if a hacker finds an obfuscation bypass that fools the policy, the OS Kernel (via Seccomp/Seatbelt/Low-IL) will physically block the write attempt."
- **Value**: "This is **Defense in Depth**. Code-level logic may fail, but Kernel-level isolation remains constant."

---

## 🔒 Scenario 3: Proactive Lockdown (Demo 2 - Malicious Block)
**Action**: Run `cargo run --example demo_malicious_block`

**Key Narrative**:
- "Hackers don't give up after one try. They probe. They try `base64`. They try `curl`."
- "Observe: Our **Deny Fuse** notices the repetitive malicious behavior. After 2 attempts, the Agent is **locked out globally**."
- "Even legitimate tools are now blocked for this session. We stop the attack before the next payload can even be generated."
- **Quantitative Point**: "**0 successful destructive writes** after 100+ attempts."

---

## 📜 Scenario 4: Verifiable Trust (Demo 1 - Happy Path)
**Action**: Run `cargo run --example demo_happy_path` (Focus on Signed Receipt)

**Key Narrative**:
- "For heavily regulated industries (Finance, Gov, Healthcare), 'Trust Me' isn't enough."
- "We provide **Signed Execution Receipts**. Every single tool call is cryptographically signed by the SDK."
- "This receipt proves: Which policy version was active, what command was run, and that it was executed inside a hardened sandbox."
- **Value**: "This satisfies the **Zero Trust** requirement for AI workloads."

---

## 🏥 Scenario 5: Infrastructure Transparency (Demo 3 - Transparency)
**Action**: Run `cargo run --example demo_transparency`

**Key Narrative**:
- "Security shouldn't be a black box. Your DevOps team needs to know exactly what is protected."
- "The **Capability Doctor** provides a real-time status report of the host's security posture."
- "**No guessing**: You can see exactly which UCM capabilities are enforced on this node."

---

## 📊 Summary Comparison Table (Final Slide)

| Feature | Default Framework | agent-guard |
| :--- | :--- | :--- |
| **Logic Bypass Defense** | ❌ None ( brittle prompts) | ✅ **OS-Kernel Isolation** |
| **Audit Integrity** | ❌ Modifiable text logs | ✅ **Ed25519 Signed Receipts** |
| **Attack Response** | ❌ Passive logging | ✅ **Proactive Deny Fuse** |
| **Deployment Visibility**| ❌ Black box | ✅ **Capability Doctor (UCM)** |
| **Compliance Readiness** | ❌ Manual audit | ✅ **SIEM-ready Webhooks** |

---

## 🏁 Call to Action
**Speaker**: "agent-guard moves your AI deployment from 'Experimental' to 'Enterprise-Ready'. It’s the final barrier between a subverted LLM and your critical infrastructure."
