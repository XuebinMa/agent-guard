# agent-guard

> Policy-driven security enforcement SDK for AI agents — Rust workspace.

`agent-guard` is a composable Rust library that intercepts AI agent tool invocations, evaluates them against a declarative YAML policy, and produces structured `Allow / Deny / AskUser` decisions with a full audit trail.

## Platform Support

| Platform | Status |
|---|---|
| Linux | Supported (policy enforcement). OS-level sandbox (seccomp/namespaces) planned for Phase 2. |
| macOS | Experimental. Policy enforcement works; OS-level sandbox not yet implemented. |
| Windows | Not yet implemented. |

## Workspace Structure

```
agent-guard/
├── crates/
│   ├── agent-guard-core/       # Core types, policy engine, audit events
│   ├── agent-guard-validators/ # Bash and path validators (ported from claw-code)
│   ├── agent-guard-sandbox/    # Sandbox trait + NoopSandbox stub
│   └── agent-guard-sdk/        # High-level Guard API + examples
├── policy.example.yaml
└── Cargo.toml                  # Workspace root
```

Dependency direction (no cycles):

```
sdk → core + validators + sandbox
validators → core
sandbox → core
```

## Quick Start

```bash
git clone https://github.com/XuebinMa/agent-guard
cd agent-guard
cargo run -p agent-guard-sdk --example quickstart
```

### Quickstart output

```
=== agent-guard quickstart ===

[ALLOW    ] Safe read
[DENY     ] Dangerous rm -rf
              reason: payload matched deny rule: prefix:rm -rf (DENIED_BY_RULE)
              rule  : tools.bash.deny[0]
[DENY     ] Curl-pipe-bash
              reason: payload matched deny rule: regex:curl.*\|.*bash (DENIED_BY_RULE)
              rule  : tools.bash.deny[2]
[ASK_USER ] Git push (ask)
              prompt: Confirmation required: rule 'prefix:git push' matched
[DENY     ] Read /etc/passwd
              reason: path matched deny_paths rule: /etc/** (PATH_OUTSIDE_WORKSPACE)
              rule  : tools.read_file.deny_paths[0]
[DENY     ] AWS metadata
              reason: payload matched deny rule: regex:^https?://169\.254\.169\.254 (DENIED_BY_RULE)
              rule  : tools.http_request.deny[0]
[DENY     ] Untrusted write
              reason: trust level 'untrusted' does not permit tool 'bash' which requires 'WorkspaceWrite' mode
```

## Inline API

```rust
use agent_guard_sdk::{Guard, Tool, Context, TrustLevel, GuardDecision};

let guard = Guard::from_yaml(r#"
version: 1
default_mode: workspace_write
tools:
  bash:
    deny:
      - prefix: "rm -rf"
      - regex: "curl.*\\|.*bash"
    ask:
      - prefix: "git push"
audit:
  enabled: true
  output: stdout
"#).unwrap();

let ctx = Context {
    trust_level: TrustLevel::Trusted,
    agent_id: Some("my-agent".to_string()),
    ..Default::default()
};

match guard.check_tool(Tool::Bash, "rm -rf /tmp", ctx) {
    GuardDecision::Allow => println!("allowed"),
    GuardDecision::Deny { reason } => println!("denied: {}", reason.message),
    GuardDecision::AskUser { message, .. } => println!("ask: {}", message),
}
```

## Policy YAML (v1)

```yaml
version: 1                  # Required; only v1 accepted
default_mode: workspace_write

tools:
  bash:
    mode: workspace_write
    deny:
      - prefix: "rm -rf"
      - prefix: "sudo"
      - regex: "curl.*\\|.*bash"
    ask:
      - prefix: "git push"
    allow:
      - prefix: "cargo"

  read_file:
    deny_paths:
      - "/etc/**"
      - "**/.ssh/**"

  http_request:
    deny:
      - regex: "^https?://169\\.254\\.169\\.254"  # cloud metadata endpoint

  custom:
    acme.sql.query:
      deny:
        - regex: "(?i)drop\\s+table"

trust:
  untrusted:
    override_mode: read_only   # hard floor for untrusted actors

audit:
  enabled: true
  output: stdout               # or "file" with file_path
  include_payload_hash: true
```

See [`policy.example.yaml`](policy.example.yaml) for the full annotated reference.

### Rule matching semantics

> **Important:** `prefix:` and bare-string rules have **different** match semantics. This is a common source of misconfiguration.

| Rule syntax | Match semantics | Example |
|---|---|---|
| `- prefix: "rm -rf"` | `starts_with` — command must **start** with the token (leading whitespace ignored) | `rm -rf /` → match; `echo rm -rf` → **no match** |
| `- "DANGER"` | `contains` — token can appear **anywhere** in the payload | `echo DANGER here` → match |
| `- regex: "..."` | Standard regex, matched against full payload string | |

> **Warning — bare strings match anywhere:**
> A bare string rule like `- "secret"` will match `echo secret`, `cat /etc/secret-key`, and `export MY_SECRET=x`.
> This is **much broader** than most users expect. Unless you specifically need substring matching across the full payload, use `prefix:` instead.

**Rule of thumb:** Use `prefix:` when you want to block a specific command. Use a bare string only when you intentionally need substring matching across the entire payload string.

### Payload format for structured tools

`read_file`, `write_file`, and `http_request` require a **JSON object payload** — a raw path or URL string is rejected:

| Tool | Required JSON shape | Rejected |
|---|---|---|
| `read_file` | `{"path": "/some/file"}` | `"/some/file"` |
| `write_file` | `{"path": "/out.txt", "content": "..."}` | `"/out.txt"` |
| `http_request` | `{"url": "https://..."}` | `"https://..."` |

Malformed JSON → `INVALID_PAYLOAD`. Missing required field → `MISSING_PAYLOAD_FIELD`. Both result in `Deny`.

## Audit Event Format (JSONL)

Each tool call emits one JSON line when `audit.enabled: true`:

| Field | Type | Description |
|---|---|---|
| `timestamp` | ISO-8601 UTC | When the decision was made |
| `request_id` | UUID v4 | Unique per call |
| `session_id` | string? | From `Context.session_id` |
| `agent_id` | string? | From `Context.agent_id` |
| `actor` | string? | From `Context.actor` |
| `tool` | string | `bash`, `read_file`, `write_file`, `http_request`, or custom id |
| `payload_hash` | hex string \| null | SHA-256 of raw payload when `include_payload_hash: true`; `null` otherwise. Raw payload is never logged. |
| `decision` | `allow` \| `deny` \| `ask_user` | Outcome |
| `code` | string? | Decision code, e.g. `DENIED_BY_RULE`, `ASK_REQUIRED` |
| `message` | string? | Human-readable reason |
| `details` | JSON? | Structured extension data |
| `matched_rule` | string? | Policy rule path, e.g. `tools.bash.deny[0]` |

Example:

```json
{"timestamp":"2026-04-05T05:23:25Z","request_id":"c74cf2fe-...","session_id":"s1","agent_id":"my-agent","actor":"ci-bot","tool":"bash","payload_hash":"b0ace843...","decision":"deny","code":"DENIED_BY_RULE","message":"payload matched deny rule: prefix:rm -rf","details":null,"matched_rule":"tools.bash.deny[0]"}
```

## Running Examples

```bash
# 7 scenarios: allow / deny / ask
cargo run -p agent-guard-sdk --example quickstart

# Load policy.example.yaml, exercise builtin + custom tools
cargo run -p agent-guard-sdk --example policy_demo

# Live JSONL audit output
cargo run -p agent-guard-sdk --example audit_demo
```

## Decision Codes

| Code | Meaning |
|---|---|
| `DENIED_BY_RULE` | Matched a `deny` rule in policy |
| `ASK_REQUIRED` | Matched an `ask` rule — user confirmation needed |
| `INSUFFICIENT_PERMISSION_MODE` | Trust level's mode floor blocks this tool |
| `PATH_OUTSIDE_WORKSPACE` | Path matched a `deny_paths` rule |
| `NOT_IN_ALLOW_LIST` | `allow_paths` is configured but path is not in the list |
| `PATH_TRAVERSAL` | `../` detected outside declared workspace |
| `WRITE_IN_READ_ONLY_MODE` | Write operation in `read_only` mode |
| `DESTRUCTIVE_COMMAND` | Destructive pattern detected by bash validator |
| `INVALID_PAYLOAD` | Tool payload is not valid JSON |
| `MISSING_PAYLOAD_FIELD` | JSON payload is missing a required field (`path` or `url`) |
| `UNTRUSTED_PATH` | Path outside trusted root |
| `POLICY_LOAD_ERROR` | Policy file failed to load/parse |
| `INTERNAL_ERROR` | Unexpected internal error |

## Relationship to claw-code

`agent-guard` is a clean extraction of the security enforcement layer from [claw-code](https://github.com/ultraworkers/claw-code), a community reimplementation of Claude Code's architecture. Business logic from `bash_validation.rs` and `trust_resolver.rs` is preserved; the only changes are:

- Removed dependencies on claw-code-internal crates
- Changed `use crate::permissions::PermissionMode` to a locally-defined enum in the validators crate
- Restructured into a proper Cargo workspace with separated concerns
- Fixed a bug: `tee` was incorrectly listed as read-only in the upstream source

## License

MIT
