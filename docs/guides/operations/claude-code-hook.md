# Claude Code PreToolUse Hook

| Field | Details |
| :--- | :--- |
| **Status** | 🟡 Dogfood (v0.2.0-rc1) |
| **Audience** | Anyone running `guard-hook` against their own Claude Code sessions |
| **Version** | 0.1 |
| **Last Reviewed** | 2026-05-20 |
| **Related Docs** | [Observability](observability.md), [Deployment Guide](deployment-guide.md) |

---

`guard-hook` (`crates/guard-hook`) is a small adapter that bridges Claude Code's `PreToolUse` hook event to the Guard SDK. Reads `PreToolUse` JSON from stdin, maps `tool_name` / `tool_input` to a `Tool` + payload, runs `Guard::check`, and emits a `hookSpecificOutput` response on stdout. Wiring lives in `~/.claude/settings.json`.

This page documents friction that surfaces when you actually run it against your own Claude Code workflow — i.e. things the SDK is doing correctly, but that look like false positives until you understand why.

---

## Hard kill switch

If the hook is in your way, start Claude Code with:

```bash
AGENT_GUARD_HOOK=off claude
```

`guard-hook` checks this env var first and emits an immediate allow without touching policy or validators. Use it when you need to ship one specific thing past a deny; do not make it your default — that is the same as not running the hook.

---

## Known friction

### 1. Top-level command substitution in `git commit -m`

**Symptom.** Claude Code's default commit recipe is:

```bash
git commit -m "$(cat <<'EOF'
<commit body>
EOF
)"
```

`guard-hook` denies this with `DENIED_BY_RULE`:

> `Command contains shell substitution '$(' whose inner command cannot be validated`

**Why this is not a validator bug.** Top-level `$( … )` is the canonical injection vector. The shell evaluates the inner command *before* `git commit` ever sees its argument, so a payload like `git commit -m "$(rm -rf ~)"` actually runs `rm -rf ~`. The substitution gate refuses to evaluate the inner text on the model's behalf because doing so safely requires re-implementing shell semantics inside the validator. We do not.

The same posture applies to nested single substitutions (`echo "$(whoami)"`) and to backticks at top level.

**Workaround.** Use stdin instead of substitution:

```bash
git commit -F - <<'EOF'
<commit body>
EOF
```

`-F -` reads the message from stdin; the heredoc body is literal (single-quoted delimiter), so backticks and `$` inside the message are not interpreted. This form is allowed and produces the same commit message.

For programmatic flows where stdin is awkward, write the message to a workspace-internal file first, then `git commit -F path/to/msg && rm path/to/msg`.

### 2. Markdown backticks inside a single-quoted heredoc body

Earlier `guard-hook` builds (≤ commit `8de86c3`) denied:

```bash
cat <<'EOF'
markdown with `code` spans inside
EOF
```

This is a real false positive — the single-quoted delimiter (`<<'EOF'`) makes the body literal, so the backticks are not substitutions. Fixed in commit `e1822ed` (quoting-aware substitution walker). If you see this deny on a recent commit, your installed binary is stale — rebuild:

```bash
cargo install --path crates/guard-hook --force
```

### 3. `write_file` to paths outside the workspace

`guard-hook` reports `PATH_TRAVERSAL` when Claude Code tries to write outside the `working_directory` it was given. In dogfood you will see this on at least two real paths:

- `/private/tmp/<scratch>` — Claude Code's transient scratch files
- `~/.claude/projects/<slug>/memory/**` — Claude Code's own session memory

Whether these should be allowed is a **policy** decision, not a validator one. The validator is correctly refusing to write outside the declared workspace; what counts as "workspace-adjacent but safe" is something the user-level policy YAML expresses.

Treatment is tracked separately and not yet final; see the `runtime-hook-dogfood` memory.

---

## Verifying the hook without restarting Claude

Pipe a synthetic `PreToolUse` event straight into the binary:

```bash
python3 -c "import json; print(json.dumps({
  'hook_event_name': 'PreToolUse',
  'tool_name': 'Bash',
  'tool_input': {'command': 'echo hi'},
  'cwd': '/your/working/dir',
}))" | ~/.cargo/bin/guard-hook check \
  --policy ~/.claude/agent-guard-policy.yaml \
  --agent-id smoke-test
```

A passing call prints a `hookSpecificOutput` JSON object on stdout; a deny prints the `DecisionCode` and message on stderr with exit 0 (the hook never blocks the agent on internal errors — exit code always 0, decision lives in the JSON body).

After any change under `crates/guard-hook/` or `crates/agent-guard-validators/`, reinstall to pick it up in the next Claude Code session:

```bash
cargo install --path crates/guard-hook --force
```
