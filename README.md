# agent-guard

> AI Agent permission enforcement and sandbox security SDK — extracted and adapted from [claw-code](https://github.com/ultraworkers/claw-code).

`agent-guard` is a standalone Rust library that provides a layered security enforcement runtime for AI agents. It intercepts tool invocations, analyzes bash command intent, enforces workspace boundaries, and resolves filesystem trust — all without modifying your agent's business logic.

## Why

AI agents that can execute arbitrary code, write files, and run shell commands represent a real attack surface. `agent-guard` gives you a composable, policy-driven security layer that can be dropped in front of any tool execution path:

- **Defense in depth** — multiple independent enforcement layers, not a single blacklist
- **Semantic analysis** — classifies bash commands by *intent* (ReadOnly / Write / Destructive / Network / SystemAdmin), not keyword matching
- **Workspace isolation** — file writes are bounded to a declared workspace root
- **Trust resolution** — path-based allowlist/denylist with interactive approval fallback
- **Hook injection** — external systems (CI, policy engines) can override decisions at runtime

## Architecture

```
AI Agent (any framework)
    │
    ▼  tool call
PermissionEnforcer          ← first gate: mode check + rule matching
    ├── PermissionPolicy    ← allow / deny / ask rules; hook override
    ├── BashValidator       ← semantic intent classification
    ├── TrustResolver       ← path trust: AutoTrust / RequireApproval / Deny
    └── SandboxConfig       ← filesystem isolation mode (WorkspaceOnly / AllowList / Off)
    │
    ▼  approved
Tool Execution
```

## Quick Start

### Prerequisites

- Rust 1.70+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)

### Add to your project

```toml
# Cargo.toml
[dependencies]
agent-guard = { git = "https://github.com/csmaxuebin/agent-guard" }
```

### Basic usage

```rust
use agent_guard::{
    EnforcementResult, PermissionEnforcer, PermissionMode, PermissionPolicy,
    RuntimePermissionRuleConfig,
};

fn main() {
    // Read-only mode: only safe, non-mutating commands allowed
    let policy = PermissionPolicy::new(PermissionMode::ReadOnly)
        .with_tool_requirement("bash", PermissionMode::DangerFullAccess);

    let enforcer = PermissionEnforcer::new(policy);

    match enforcer.check_bash("cat README.md") {
        EnforcementResult::Allowed => println!("allowed"),
        EnforcementResult::Denied { reason, .. } => println!("denied: {reason}"),
    }

    // Rule-based: allow git, deny rm -rf, ask for everything else
    let rules = RuntimePermissionRuleConfig::new(
        vec!["bash(git:*)".to_string()],          // allow
        vec!["bash(rm -rf:*)".to_string()],       // deny
        vec![],
    );
    let policy2 = PermissionPolicy::new(PermissionMode::WorkspaceWrite)
        .with_permission_rules(&rules);
    let enforcer2 = PermissionEnforcer::new(policy2);

    match enforcer2.check("bash", r#"{"command":"rm -rf /tmp/x"}"#) {
        EnforcementResult::Allowed => println!("allowed"),
        EnforcementResult::Denied { reason, .. } => println!("denied: {reason}"),
    }
}
```

## Permission Modes

| Mode | Description |
|---|---|
| `ReadOnly` | Only non-mutating operations permitted |
| `WorkspaceWrite` | File writes restricted to declared workspace root |
| `DangerFullAccess` | All operations permitted (use with rule-based restrictions) |
| `Prompt` | Every tool call triggers an interactive approval prompt |
| `Allow` | Rule-matched operations pass through unconditionally |

## Command Intent Classification

`classify_intent(cmd)` returns one of:

| Intent | Example commands |
|---|---|
| `ReadOnly` | `ls`, `cat`, `grep`, `git status`, `find` |
| `Write` | `cp`, `mv`, `mkdir`, `touch`, `chmod` |
| `Destructive` | `rm -rf`, `shred`, `mkfs` |
| `Network` | `curl`, `wget`, `ssh`, `scp` |
| `ProcessManagement` | `kill`, `pkill`, `nohup` |
| `PackageManagement` | `apt`, `brew`, `cargo install` |
| `SystemAdmin` | `sudo`, `systemctl`, `mount` |

## Running the Examples

Clone and run any of the three bundled demos:

```bash
git clone https://github.com/csmaxuebin/agent-guard
cd agent-guard

# Show five permission modes in action
cargo run --example permission_demo

# Bash command intent classification + dangerous pattern detection
cargo run --example bash_guard_demo

# Sandbox configuration + filesystem trust resolver
cargo run --example sandbox_demo
```

### permission_demo output (excerpt)

```
=== Agent Guard - Permission Demo ===

--- Mode: ReadOnly ---
  [ALLOW] read_file
  [DENY]  write_file
         reason: tool 'write_file' requires workspace-write but active mode is read-only
  [DENY]  bash rm -rf
         reason: command blocked in read-only mode: contains write/destructive operation
  [ALLOW] bash cat file
  [DENY]  file write in workspace
         reason: ...

--- Mode: WorkspaceWrite ---
  [ALLOW] write in workspace
  [DENY]  write outside workspace
         reason: path '/etc/passwd' is outside the workspace root '/workspace'
```

### bash_guard_demo output (excerpt)

```
--- Command Intent Classification ---
  📖 [ReadOnly]  ls -la
  📖 [ReadOnly]  cat README.md
  💥 [Destructive] rm -rf /tmp/test
  💥 [Destructive] rm -rf /
  🌐 [Network]   curl https://example.com
  🔐 [SystemAdmin] sudo apt-get install vim

--- Destructive Command Check ---
  ⚠️  DANGER: rm -rf /
  ⚠️  DANGER: :(){ :|:& };:
  ✅ Safe: ls -la
```

## Running the Tests

```bash
# All tests
cargo test

# Original integration tests (35 cases)
cargo test --test integration_test

# Industry-grade tests (41 passed + 8 ignored/future)
cargo test --test integration_test_industry_grade
```

## Module Reference

| Module | Source | Responsibility |
|---|---|---|
| `permissions` | claw-code (verbatim) | `PermissionPolicy`, `PermissionMode`, rule evaluation, hook override |
| `permission_enforcer` | claw-code (verbatim) | `PermissionEnforcer`: `check()`, `check_bash()`, `check_file_write()` |
| `bash_validation` | claw-code (verbatim) | Intent classification, read-only guard, destructive pattern detection, path traversal |
| `trust_resolver` | claw-code + extensions | Path allowlist/denylist, interactive trust prompt detection |
| `sandbox` | claw-code (verbatim) | `SandboxConfig`, `FilesystemIsolationMode` (Linux namespace isolation) |
| `config` | new (minimal) | `RuntimePermissionRuleConfig` stub used by policy engine |

## Relationship to claw-code

This library is a **clean extraction** of the security enforcement layer from [claw-code](https://github.com/ultraworkers/claw-code), a community reimplementation of Claude Code's architecture. Core business logic is preserved verbatim; the only changes are:

- Removed dependencies on `telemetry`, `plugins`, and other claw-code-internal crates
- Replaced `crate::json::JsonValue` with `serde_json::Value`
- Added `classify_intent` re-export and minor API ergonomics
- Fixed a bug: `tee` was incorrectly listed as a read-only command in the enforcer whitelist

## Known Limitations

- **macOS sandboxing**: `sandbox.rs` uses Linux `unshare` syscalls. On macOS, namespace isolation is a no-op — only workspace path checking applies.
- **No PII detection**: content-level privacy scanning is not included.
- **No audit log**: tool call history is not persisted.
- **Static policy**: `PermissionPolicy` is immutable after construction; hot-reload is not supported.

The 8 `#[ignore]` tests in `integration_test_industry_grade.rs` document known gaps (chain-command bypass, command substitution exfiltration, symlink escape, etc.) that represent future hardening targets.

## License

MIT — same as the upstream claw-code project.
