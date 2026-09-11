# agent-guard-plugin

One-command setup for the [agent-guard](https://github.com/XuebinMa/agent-guard) advisory outbound hook in Claude Code.

This path is intentionally fail-open on installation/runtime errors and does
not own Git credentials or execution. Treat it as an advisory host integration,
not an isolation boundary against an agent that can bypass the hook.

```bash
npx agent-guard-plugin init
install -m 600 /dev/null ~/.agent-guard/broker.gitconfig
```

The second line creates the host-owned configuration required by
`agent-guard push`; keep it outside any agent-writable checkout. See the
[plugin guide](https://github.com/XuebinMa/agent-guard/blob/main/docs/guides/operations/claude-code-plugin.md).

## What `init` does

1. **Installs both matching binaries** with `cargo install <crate> --version <plugin-version> --locked --force` (Rust required). An existing binary is reused only after its `--version` output exactly matches the plugin:
   - `guard-hook` — the PreToolUse gate itself.
   - `agent-guard-cli`, providing `agent-guard` — the broker path the gate *names*. When the gate stops a push it tells you to run `agent-guard push`, so installing the gate without this leaves you at a `command not found`.

   If cargo is missing, or one install fails, it says which binary is absent and what it costs you, then continues — the hook remains advisory and fails open until `guard-hook` exists.
2. **Writes the policy** to `~/.claude/agent-guard/policy.yaml` (the bundled outbound preset, with audit routed to `~/.claude/agent-guard/audit.jsonl` so the hook's stdout stays clean).
3. **Wires the hook** into `~/.claude/settings.json` under `PreToolUse` for `Bash`, `Write`, `Edit`, and `WebFetch`. The edit is idempotent and preserves every other setting and hook.

Restart Claude Code afterwards so the hook loads.

## Options

| Option | Effect |
| :--- | :--- |
| `--dry-run` | Show changes without writing anything |
| `--force` | Overwrite an existing policy file |
| `--binary-only` | Only install the binaries (use with the marketplace plugin) |
| `--skip-binary` | Skip `cargo install` (assume the binaries are present) |
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
