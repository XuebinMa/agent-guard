# agent-guard-plugin

One-command setup for the [agent-guard](https://github.com/XuebinMa/agent-guard) advisory outbound hook in Claude Code.

The `v0.2.0` source is not published to npm or crates.io yet. From the repository
root, install and initialize the matching checkout with:

This path is intentionally fail-open on installation/runtime errors and does
not own Git credentials or execution. Treat it as an advisory host integration,
not an isolation boundary against an agent that can bypass the hook.

```bash
cargo install --path crates/guard-hook --locked
node packages/agent-guard-plugin/bin/cli.js init --skip-binary
```

After the synchronized `v0.2.0` release, `npx agent-guard-plugin init` becomes
the standalone setup path and installs the exact same `guard-hook` version. The
current npm `latest` tag is still `0.2.0-rc1`, so it is not a substitute for
these source-checkout instructions. See the [plugin guide](https://github.com/XuebinMa/agent-guard/blob/main/docs/guides/operations/claude-code-plugin.md).

## What `init` does

1. **Installs the matching binary** with `cargo install guard-hook --version <plugin-version> --locked` (Rust required). If cargo is missing it prints manual instructions and continues — the hook remains advisory and fails open until the binary exists.
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
