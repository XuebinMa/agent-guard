# Demo Asset Workflow

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Repeatable Workflow |
| **Audience** | Maintainers, DevRel, Contributors |
| **Version** | 1.0 |
| **Last Reviewed** | 2026-04-14 |
| **Related Docs** | [Launch Kit](launch-kit.md), [Attack Demo Playbook](../getting-started/attack-demo-playbook.md), [Three-Minute Proof](../getting-started/three-minute-proof.md) |

---

This is a maintainer workflow document, not a general product entry point. Use it when you are refreshing screenshots or recording clips after the core proof and messaging are already settled.

---

This guide explains how to create stable visual assets for `agent-guard` demos without improvising each time.

Use it when you need:

- a fresh terminal screenshot for the README
- a short screen recording for a post or issue comment
- a consistent visual style across demo assets

---

## 1. Canonical Demo To Use

Use the proof demo as the default source asset:

```bash
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:proof --prefix crates/agent-guard-node
```

Why this demo:

- it is short
- it shows allow and block behavior clearly
- it matches the current project wedge: shell and high-risk tool protection

---

## 2. Canonical Screenshot Asset

The repository now includes a reusable screenshot asset:

- [demo-proof-terminal.svg](../../assets/demo-proof-terminal.svg)

Use that asset by default in:

- README updates
- docs landing pages
- issue comments
- release notes

Only replace it when the proof demo output or messaging changes materially.

---

## 3. How To Refresh The Screenshot

When the proof demo output changes:

1. Run `npm run demo:proof --prefix crates/agent-guard-node`.
2. Confirm the allow/block story is still clean and readable.
3. Update [demo-proof-terminal.svg](../../assets/demo-proof-terminal.svg) so the text matches the current output.
4. Re-check the README and docs pages that embed the asset.

The goal is not pixel perfection. The goal is a trustworthy visual proof that matches the live demo.

---

## 4. Recording A Short Terminal Clip

Recommended sequence:

1. Open a clean terminal window.
2. Increase font size before recording.
3. Run `npm run demo:proof --prefix crates/agent-guard-node`.
4. Pause briefly after:
   - `with guard: allowed`
   - `with guard: blocked` for `git push`
   - `with guard: blocked` for `rm -rf /`
5. Keep the total clip under 60 seconds.

Recommended narration:

- “This is the same shell-like tool path before and after `agent-guard`.”
- “Safe commands still work.”
- “Risky commands do not silently execute.”
- “Destructive commands get stopped before they reach the host.”

---

## 5. Visual Rules

Keep demo assets consistent:

- prefer one dark terminal style
- keep output zoomed in enough to read on mobile
- avoid showing unrelated shell history
- do not include personal tokens, usernames, or local secrets
- keep the blocked lines visible without scrolling if possible

---

## 6. Where To Link After Sharing

Whenever you post a screenshot or clip, pair it with:

1. [Three-Minute Proof](../getting-started/three-minute-proof.md)
2. [Node Quickstart](../../../crates/agent-guard-node/examples/quickstart/README.md)
3. [Framework Support Matrix](../../framework-support-matrix.md)

That gives viewers:

- proof
- a runnable next step
- an honest support-status view

---

## 7. Quality Check Before Publishing

Before sharing externally, verify:

- the screenshot still matches the current demo output
- the demo commands in the post are copyable
- the README and docs links still work
- the clip stays focused on one story: allowed vs blocked tool calls

If the visual asset is impressive but the next step is unclear, conversion drops quickly.
