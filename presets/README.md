# Presets

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Available (v0.2.0-rc1) |
| **Audience** | Anyone running an AI coding agent against this codebase |
| **Last Reviewed** | 2026-05-21 |

Drop-in policy templates for common agent-guard scenarios. A preset is a complete `policy.yaml` you can hand to the SDK or to `guard-hook` with one `--policy` flag — no rule writing required.

---

## What's here

| File | Coverage | When to use |
| :--- | :--- | :--- |
| `coding-agent-outbound.yaml` | All 5 outbound-action categories for AI coding agents: code egress, package release, artifact egress, remote mutation, destructive shell. | Default starting point for Claude Code / Cursor / Codex CLI / Aider users who want safe defaults without writing rules. |

If you do not see a preset for your scenario yet, the closest match is usually `coding-agent-outbound.yaml`; copy it and trim.

---

## How to adopt

### Claude Code (PreToolUse hook)

Wire `guard-hook` into `~/.claude/settings.json` (see `docs/guides/operations/claude-code-hook.md` for the full setup) and point its `--policy` flag at the preset:

```bash
guard-hook check --policy /abs/path/to/presets/coding-agent-outbound.yaml --agent-id claude-code
```

### Programmatic (Rust SDK)

```rust
use agent_guard_sdk::Guard;

let guard = Guard::from_yaml_file("presets/coding-agent-outbound.yaml")?;
```

### Programmatic (Node binding)

```js
const { Guard } = require("agent-guard-node");
const guard = Guard.fromYamlFile("presets/coding-agent-outbound.yaml");
```

### Copy and edit

The preset is plain YAML; copy it into your project and tighten or loosen rules in place. The header comment documents every rule with the moment it catches and the rationale, so edits are self-explanatory.

---

## `coding-agent-outbound.yaml` — what it does

Five categories, mirroring the strategic outbound-action frame:

| Category | Example commands | Verdict |
| :--- | :--- | :--- |
| Code egress | `git push`, `git push --force` | `git push` → ask. `git push --force` / `-f` / `--force-with-lease` / `--mirror` → deny. |
| Package release | `npm publish`, `cargo publish`, `gem push`, `twine upload`, `pip` upload via `setup.py` | ask |
| Artifact egress | `docker push`, `podman push`, `buildx --push`, `gh release ...` | ask |
| Remote mutation (URL-only) | HTTP to cloud metadata, RFC1918, loopback | deny |
| Destructive shell | `rm -rf /`, `rm -rf ~`, `mkfs`, `dd if=...of=/dev/...`, `sudo`, curl-pipe-bash | deny. Recoverable destructive (`rm -rf <some>`, `git reset --hard`, `git clean -fd`, `find … -delete`) → ask. |

Friction-free passthrough is the default for everything else inside the workspace: `git status`, `git diff`, `git commit`, `cargo build`, `cargo test`, `npm test`, etc. — no rule fires.

### Known gaps in this preset

1. **HTTP method-aware filtering.** The current `http_request` payload schema is URL-only; the validator cannot see whether a request is a `POST` vs `GET`. The preset compensates by URL-level denies for the highest-value destinations (cloud metadata, RFC1918, loopback). If you need true "ask before any non-local mutating method," do it host-side: wrap your HTTP tool to set a different `tool` name (e.g. `Custom("http.mutate")`) for non-`GET` calls, then add a per-tool rule in policy. The validator will be extended with a `method` matcher in a future sprint.

2. **Cluster / environment awareness.** `kubectl apply`, `terraform apply`, `pulumi up`, etc. land in `ask` regardless of whether they target a dev cluster or production. There is no way to express "ask for prod, allow for dev" without parsing kubeconfig / state. Override per-environment in your own copy.

3. **Trust override deliberately omitted.** The preset does **not** set `trust.untrusted.override_mode`. Doing so would force untrusted agents (the harness default) into `read_only` and block every shell call before the ask/deny rules could run. Add your own trust tiers on top when you classify agents.

---

## Verifying behaviour

Pipe a synthetic `PreToolUse` event straight into the binary to test how the preset rules an exact command without restarting your agent:

```bash
python3 -c "import json; print(json.dumps({
  'hook_event_name': 'PreToolUse',
  'tool_name': 'Bash',
  'tool_input': {'command': 'git push origin main'},
  'cwd': '/your/project',
}))" | guard-hook check \
  --policy presets/coding-agent-outbound.yaml \
  --agent-id smoke-test
```

The output `permissionDecision` field will be one of `allow`, `ask`, or `deny`.

---

## Contributing a new preset

A new preset should:

- Be a complete `PolicyFile` (top-level `version: 1`, `default_mode`, `tools`, optional `trust` / `anomaly` / `audit`).
- Document every rule with a short comment naming the moment it catches and the reason.
- Default to friction-free for workspace-internal work; the value of a preset is in what it gates, not what it adds friction to.
- Avoid trust overrides unless the preset itself is explicitly for a trust-tiered host model.
- Be smoke-testable: include at least 5 representative commands across the scenarios it covers, with expected verdicts (PR description is fine — no test fixture required).

Open a PR with the file under `presets/` and a one-row addition to the "What's here" table above.
