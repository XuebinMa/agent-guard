# agent-guard-plugin

One-command setup for the [agent-guard](https://github.com/XuebinMa/agent-guard) outbound gate in Claude Code.

`npx agent-guard-plugin init` installs the `guard-hook` binary, drops the outbound policy, and wires a `PreToolUse` hook into your `~/.claude/settings.json` that gates `git push`, `npm publish`, `docker push`, `gh release`, non-local HTTP mutations, and `rm -rf` — before they happen.

```bash
npx agent-guard-plugin init
```

This is the **standalone** setup path. If you prefer Claude Code's native plugin system, use the marketplace instead (`/plugin marketplace add XuebinMa/agent-guard`) and run `npx agent-guard-plugin init --binary-only` just to install the binary — see [the plugin guide](https://github.com/XuebinMa/agent-guard/blob/main/docs/guides/operations/claude-code-plugin.md).

## What `init` does

1. **Installs the binary** with `cargo install --git … guard-hook` (Rust required). If cargo is missing it prints manual instructions and continues — the hook fails open until the binary exists, so nothing is ever blocked by a partial setup.
2. **Writes the policy** to `~/.claude/agent-guard/policy.yaml` (the bundled outbound preset, with audit routed to `~/.claude/agent-guard/audit.jsonl` so the hook's stdout stays clean).
3. **Wires the hook** into `~/.claude/settings.json` under `PreToolUse` for `Bash`, `Write`, `Edit`, and `WebFetch`. The edit is idempotent and preserves every other setting and hook.

Restart Claude Code afterwards so the hook loads.

## Options

| Option | Effect |
| :--- | :--- |
| `--dry-run` | Show changes without writing anything |
| `--force` | Overwrite an existing policy file |
| `--binary-only` | Only install the binary (use with the marketplace plugin) |
| `--skip-binary` | Skip `cargo install` (assume `guard-hook` is present) |
| `--agent-id <id>` | Audit agent id recorded by the hook (default: `claude-code`) |
| `--settings <path>` | Target settings.json (default: `~/.claude/settings.json`) |

## Disable / uninstall

```bash
AGENT_GUARD_HOOK=off claude        # disable for one session
npx agent-guard-plugin uninstall   # remove the hook from settings.json
```

`uninstall` removes only agent-guard's hook entry; your policy file and the binary are left in place.

## License

MIT
