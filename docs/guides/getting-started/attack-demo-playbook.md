# Attack Demo Playbook

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Demo Asset |
| **Audience** | DevRel, Maintainers, Evaluators |
| **Version** | 1.0 |
| **Last Reviewed** | 2026-04-14 |
| **Related Docs** | [Secure Shell Tools](secure-shell-tools.md), [ChatGPT Actions Integration](chatgpt-actions.md), [Growth & Adoption Plan](../../growth-and-adoption-plan.md) |

---

This playbook gives you a repeatable, low-friction way to demonstrate the value of `agent-guard`.

It is meant for:

- README readers who want a stronger proof point
- maintainers recording demos
- technical talks or internal adoption reviews
- first-time evaluators who need to see the delta quickly

---

## 1. Demo Goal

Show the difference between:

- a tool path with no meaningful boundary
- the same tool path protected by `agent-guard`

The key message is:

> Without a guard, the tool call would flow into execution.  
> With `agent-guard`, the same input is checked and can be blocked or require approval before reaching the host.

---

## 2. Fastest Demo Command

Run:

```bash
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:attack --prefix crates/agent-guard-node
```

This runs the Node attack demo example in:

- [attack-demo](../../../crates/agent-guard-node/examples/attack-demo/README.md)

---

## 3. Demo Structure

The demo walks through three inputs:

1. safe command
2. approval-required command
3. destructive command stopped before execution

Recommended narration:

### Safe Command

- “A normal command still works.”
- “We are not trying to make the tool useless.”

### Approval-Required Command

- “A risky command does not silently execute.”
- “The boundary changes from silent execution to explicit decision.”

### Hard-Blocked Command

### Destructive Command

- “A clearly destructive command is stopped before it reaches the host execution path.”
- “Depending on the active policy and validator path, this may surface as `deny` or `ask_required`, but in either case it does not silently run.”

---

## 4. Example Inputs

Use exactly these:

- `echo hello from attack demo`
- `git push origin main`
- `rm -rf /`

Why these work well:

- easy to understand immediately
- clearly map to allow / ask / deny behavior
- recognizable to almost every technical audience

---

## 5. Expected Message

The strongest takeaway is not “look how many features we have.”

The strongest takeaway is:

- shell tools are dangerous
- unguarded paths are brittle
- `agent-guard` creates a decision boundary before execution

That is the story to keep repeating.

---

## 6. Suggested 30-Second Explanation

Use language like:

1. “This left side is what happens when a tool call goes straight into a shell handler.”
2. “This right side is the same call routed through `agent-guard`.”
3. “Safe commands still succeed.”
4. “Risky commands move to approval.”
5. “Destructive commands are blocked.”

---

## 7. Recommended Follow-Up Demos

After the attack demo, the best next demos are:

1. `npm run demo:quickstart --prefix crates/agent-guard-node`
2. `cargo run --example demo_transparency`
3. `cargo run --example demo_malicious_block`

That sequence gives:

- quick product understanding
- host capability transparency
- stronger trust and security depth

---

## 8. Recording Tips

When recording a short clip:

- keep the terminal font large
- show the command input clearly
- avoid long setup sequences
- keep the final clip under 60 seconds
- pause briefly after each blocked result

If you make only one public clip, make it the attack demo.

---

## 9. What To Avoid

Avoid making the demo about:

- abstract architecture first
- every framework at once
- every platform nuance at once
- unrealistic “all security solved” claims

The goal is clarity, not exhaustiveness.

---

## 10. Next Asset To Build

After this playbook, the next strongest public asset would be:

- a short terminal recording or GIF of the attack demo

That would give the project a more visual “proof of value” for README, social posts, and issue discussions.
