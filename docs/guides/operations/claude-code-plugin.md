# Claude Code Plugin

| Field | Details |
| :--- | :--- |
| **Status** | 🟡 Preview (v0.2.0-rc1) |
| **Audience** | Claude Code users who want the agent-guard outbound gate installed as a plugin |
| **Version** | 0.1 |
| **Last Reviewed** | 2026-05-29 |
| **Related Docs** | [Claude Code Hook](claude-code-hook.md), [Observability](observability.md) |

---

The agent-guard **Claude Code plugin** packages the [`guard-hook`](claude-code-hook.md) adapter as a one-command install. Once installed, it registers a `PreToolUse` hook that evaluates `Bash`, `Write`, `Edit`, and `WebFetch` tool calls against the bundled [outbound preset](../../../presets/coding-agent-outbound.yaml) — gating `git push`, `npm publish`, `docker push`, `gh release`, non-local HTTP mutations, and `rm -rf` before they happen.

The plugin is the distribution wrapper. The actual evaluation is done by the `guard-hook` binary; see [Claude Code Hook](claude-code-hook.md) for the decision semantics, the known friction (top-level `$(…)`, workspace-escape paths), and the content-layer scope. This page covers only install and the plugin-specific behaviour.

---

## Install

There are two install paths. Both end with the same `PreToolUse` gate; pick whichever fits your workflow.

### Option A — one command (`npx`)

```bash
npx agent-guard-plugin init
```

This installs the `guard-hook` binary (via `cargo install` — Rust required), writes the outbound policy to `~/.claude/agent-guard/policy.yaml`, and wires the hook into `~/.claude/settings.json`. The edit is idempotent and preserves your other settings and hooks. Use `--dry-run` to preview, `npx agent-guard-plugin uninstall` to remove the hook. See [`packages/agent-guard-plugin`](../../../packages/agent-guard-plugin/README.md) for all options.

### Option B — Claude Code marketplace plugin

The repo doubles as a single-plugin marketplace:

```text
/plugin marketplace add XuebinMa/agent-guard
/plugin install agent-guard@agent-guard
```

Then install the evaluation binary (the plugin **fails open** until it is present, so the gate is a no-op until you do):

```bash
cargo install --path crates/guard-hook         # from a repo checkout
# or, from anywhere:
npx agent-guard-plugin init --binary-only       # installs guard-hook only
```

`cargo install` drops `guard-hook` into `~/.cargo/bin`, which the plugin's wrapper finds automatically.

Either way, restart Claude Code (or start a new session) so the `PreToolUse` hook is loaded.

---

## How resolution works

The plugin's hook runs `scripts/guard-hook-plugin.sh`, which resolves two things and then streams the `PreToolUse` event through `guard-hook check`:

| What | Resolution order | Override |
| :--- | :--- | :--- |
| **Binary** | `guard-hook` on `PATH` → `~/.cargo/bin/guard-hook` → `${CLAUDE_PLUGIN_ROOT}/bin/guard-hook` | put `guard-hook` on `PATH` |
| **Policy** | bundled `presets/coding-agent-outbound.yaml` | `AGENT_GUARD_POLICY=/path/to/policy.yaml` |

The wrapper is **fail-open by contract**: a missing binary or missing policy emits an `allow` decision (with a one-line warning on stderr) rather than blocking your agent. A broken or partial install never stalls your workflow.

---

## Kill switch

Start Claude Code with the hook disabled for one session:

```bash
AGENT_GUARD_HOOK=off claude
```

The wrapper checks this first and emits an immediate `allow` without touching the binary or policy. Use it to ship one specific thing past a deny — not as your default.

---

## Audit output

`guard-hook` emits one JSONL audit record per evaluated call. Claude Code reads the **hook decision** from the hook's stdout, so the plugin keeps stdout reserved for exactly that one JSON line:

- With the bundled preset (`audit: { output: stdout }`), the wrapper routes the audit record to **stderr** so it is preserved without corrupting the decision channel.
- For durable forensic storage, point your policy at a file:

  ```yaml
  audit:
    enabled: true
    output: file
    file_path: ~/.local/state/agent-guard/audit.jsonl
  ```

  With `output: file` the SDK writes audit through its own file writer and stdout already carries only the decision, so the stderr split becomes a no-op.

Verify a saved receipt or aggregate the audit log with [`guard-verify`](observability.md).

---

## Overrides reference

| Env var | Effect | Default |
| :--- | :--- | :--- |
| `AGENT_GUARD_HOOK=off` | Disable the gate (immediate allow) | gate on |
| `AGENT_GUARD_POLICY` | Path to the policy YAML to enforce | bundled outbound preset |
| `AGENT_GUARD_AGENT_ID` | Agent id recorded in audit context | `claude-code-plugin` |

---

## Uninstall

```text
/plugin uninstall agent-guard@agent-guard
```

Remove the binary with `rm ~/.cargo/bin/guard-hook` if you no longer want it on `PATH`.
