//! PreToolUse JSON → agent-guard mapping and hook response emission.
//!
//! Schema reference (Claude Code PreToolUse hook input):
//!   {
//!     "session_id": "<uuid>",
//!     "transcript_path": "<path>",
//!     "cwd": "<abs path>",
//!     "tool_name": "Bash" | "Write" | "Edit" | "WebFetch" | ...,
//!     "tool_input": { ... }
//!   }
//!
//! Hook response (we always emit the modern hookSpecificOutput form):
//!   {
//!     "hookSpecificOutput": {
//!       "hookEventName": "PreToolUse",
//!       "permissionDecision": "allow" | "deny" | "ask",
//!       "permissionDecisionReason": "<text>"
//!     }
//!   }

use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use agent_guard_core::{Context, GuardDecision, GuardInput, Tool, TrustLevel};
use agent_guard_sdk::Guard;
use serde::{Deserialize, Serialize};

// ── CC hook input schema ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ClaudeCodeHookInput {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: serde_json::Value,
}

// ── CC hook response schema ───────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct HookResponse {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: HookSpecificOutput,
}

#[derive(Debug, Serialize)]
struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'static str,
    #[serde(rename = "permissionDecision")]
    permission_decision: &'static str,
    #[serde(rename = "permissionDecisionReason")]
    permission_decision_reason: String,
}

impl HookResponse {
    fn new(decision: &'static str, reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: decision,
                permission_decision_reason: reason.into(),
            },
        }
    }
}

// ── Emitters ──────────────────────────────────────────────────────────────────

pub fn emit_approve(out: &mut impl Write) {
    emit(out, HookResponse::new("allow", ""));
}

fn emit_block(out: &mut impl Write, reason: impl Into<String>) {
    emit(out, HookResponse::new("deny", reason));
}

fn emit_ask(out: &mut impl Write, reason: impl Into<String>) {
    emit(out, HookResponse::new("ask", reason));
}

fn emit(out: &mut impl Write, response: HookResponse) {
    let body = serde_json::to_string(&response).unwrap_or_else(|_| {
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":""}}"#.to_string()
    });
    let _ = writeln!(out, "{body}");
}

// ── Tool mapping ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct MappedCall {
    pub tool: Tool,
    pub payload: String,
}

/// Map a CC tool_name + tool_input to an agent-guard Tool plus the JSON
/// payload string that agent-guard validators expect. Returns `None` for
/// tools outside the audit-only wedge (those should be approved silently).
pub fn map_tool(tool_name: &str, tool_input: &serde_json::Value) -> Option<MappedCall> {
    match tool_name {
        "Bash" => {
            let command = tool_input.get("command")?.as_str()?;
            Some(MappedCall {
                tool: Tool::Bash,
                payload: serde_json::json!({ "command": command }).to_string(),
            })
        }
        "Write" => {
            let path = tool_input.get("file_path")?.as_str()?;
            let content = tool_input
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            Some(MappedCall {
                tool: Tool::WriteFile,
                payload: serde_json::json!({ "path": path, "content": content }).to_string(),
            })
        }
        "Edit" => {
            let path = tool_input.get("file_path")?.as_str()?;
            let new_string = tool_input
                .get("new_string")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            Some(MappedCall {
                tool: Tool::WriteFile,
                payload: serde_json::json!({ "path": path, "content": new_string }).to_string(),
            })
        }
        "WebFetch" => {
            let url = tool_input.get("url")?.as_str()?;
            Some(MappedCall {
                tool: Tool::HttpRequest,
                payload: serde_json::json!({ "method": "GET", "url": url }).to_string(),
            })
        }
        _ => None,
    }
}

// ── Workspace root discovery ──────────────────────────────────────────────────

/// Walk up from `cwd` looking for the nearest ancestor containing a `.git`
/// entry. Returns that ancestor when found; otherwise returns `cwd`
/// unchanged so the behaviour stays compatible with non-git invocations.
///
/// Claude Code passes its current shell `cwd` in the PreToolUse event, but
/// a developer who has `cd`'d into a sub-directory of the project sees the
/// validator's workspace bound drift along with the shell — a write to
/// `presets/README.md` from inside `crates/agent-guard-node` then fails
/// `PATH_TRAVERSAL` even though both paths are inside the same repo.
/// Anchoring to the git root matches the user's mental model of "this
/// project" instead of "where the shell happens to be", which is the
/// boundary the policy and the dogfood escape lists are written against.
///
/// `.git` is checked as either a directory (the standard case) or a file
/// (the `gitdir:` redirect used by worktrees and submodules); either form
/// is sufficient evidence that this directory is the repo root.
pub fn discover_workspace_root(cwd: &Path) -> PathBuf {
    let mut current = cwd;
    loop {
        if current.join(".git").exists() {
            return current.to_path_buf();
        }
        match current.parent() {
            Some(p) => current = p,
            None => return cwd.to_path_buf(),
        }
    }
}

// ── Top-level entry ───────────────────────────────────────────────────────────

pub fn run_check(stdin_buf: &str, policy_path: &Path, agent_id: &str, out: &mut impl Write) {
    let input: ClaudeCodeHookInput = match serde_json::from_str(stdin_buf) {
        Ok(input) => input,
        Err(error) => {
            eprintln!("guard-hook: stdin JSON parse failed: {error}; defaulting to approve");
            emit_approve(out);
            return;
        }
    };

    let Some(mapped) = map_tool(&input.tool_name, &input.tool_input) else {
        emit_approve(out);
        return;
    };

    let guard = match Guard::from_yaml_file(policy_path) {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!(
                "guard-hook: policy load failed at {}: {error}; defaulting to approve",
                policy_path.display()
            );
            emit_approve(out);
            return;
        }
    };

    let context = Context {
        agent_id: Some(agent_id.to_string()),
        session_id: input.session_id,
        actor: None,
        trust_level: TrustLevel::Untrusted,
        working_directory: input
            .cwd
            .as_deref()
            .map(|s| discover_workspace_root(Path::new(s))),
    };

    let guard_input = GuardInput {
        tool: mapped.tool,
        payload: mapped.payload,
        context,
    };

    match guard.check(&guard_input) {
        GuardDecision::Allow => emit_approve(out),
        GuardDecision::Deny { reason } => {
            let label = format_reason(
                &reason.code,
                &reason.message,
                reason.matched_rule.as_deref(),
            );
            emit_block(out, label);
        }
        GuardDecision::AskUser { message, reason } => {
            let label = format_reason(&reason.code, &message, reason.matched_rule.as_deref());
            emit_ask(out, label);
        }
    }
}

fn format_reason(
    code: &agent_guard_core::DecisionCode,
    message: &str,
    matched_rule: Option<&str>,
) -> String {
    let code_str = serde_json::to_string(code)
        .unwrap_or_else(|_| "\"UNKNOWN\"".to_string())
        .trim_matches('"')
        .to_string();
    match matched_rule {
        Some(rule) => format!("[{code_str}] {message} (rule={rule})"),
        None => format!("[{code_str}] {message}"),
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_bash_command() {
        let input = serde_json::json!({ "command": "ls -la" });
        let mapped = map_tool("Bash", &input).expect("Bash should map");
        assert_eq!(mapped.tool, Tool::Bash);
        assert!(mapped.payload.contains("ls -la"));
    }

    #[test]
    fn maps_write_with_file_path_and_content() {
        let input = serde_json::json!({ "file_path": "/tmp/a.txt", "content": "hi" });
        let mapped = map_tool("Write", &input).expect("Write should map");
        assert_eq!(mapped.tool, Tool::WriteFile);
        assert!(mapped.payload.contains("/tmp/a.txt"));
        assert!(mapped.payload.contains("hi"));
    }

    #[test]
    fn maps_edit_new_string_to_content() {
        let input = serde_json::json!({
            "file_path": "/tmp/a.txt",
            "old_string": "foo",
            "new_string": "bar"
        });
        let mapped = map_tool("Edit", &input).expect("Edit should map");
        assert_eq!(mapped.tool, Tool::WriteFile);
        assert!(mapped.payload.contains("bar"));
        assert!(!mapped.payload.contains("foo"));
    }

    #[test]
    fn maps_webfetch_to_http_get() {
        let input = serde_json::json!({ "url": "https://example.com" });
        let mapped = map_tool("WebFetch", &input).expect("WebFetch should map");
        assert_eq!(mapped.tool, Tool::HttpRequest);
        assert!(mapped.payload.contains("example.com"));
        assert!(mapped.payload.contains("GET"));
    }

    #[test]
    fn unknown_tool_returns_none() {
        let input = serde_json::json!({});
        assert!(map_tool("Read", &input).is_none());
        assert!(map_tool("Task", &input).is_none());
        assert!(map_tool("mcp__github__create_issue", &input).is_none());
    }

    #[test]
    fn bash_missing_command_returns_none() {
        let input = serde_json::json!({});
        assert!(map_tool("Bash", &input).is_none());
    }

    #[test]
    fn write_missing_file_path_returns_none() {
        let input = serde_json::json!({ "content": "hi" });
        assert!(map_tool("Write", &input).is_none());
    }

    #[test]
    fn run_check_with_bad_stdin_emits_approve() {
        let mut out = Vec::new();
        run_check(
            "not json at all",
            Path::new("/nonexistent.yaml"),
            "test",
            &mut out,
        );
        let body = String::from_utf8(out).unwrap();
        assert!(body.contains("\"permissionDecision\":\"allow\""));
    }

    #[test]
    fn run_check_with_unmappable_tool_emits_approve() {
        let mut out = Vec::new();
        let stdin = r#"{"tool_name":"Read","tool_input":{"file_path":"/tmp/x"}}"#;
        run_check(stdin, Path::new("/nonexistent.yaml"), "test", &mut out);
        let body = String::from_utf8(out).unwrap();
        assert!(body.contains("\"permissionDecision\":\"allow\""));
    }

    #[test]
    fn run_check_with_missing_policy_emits_approve() {
        let mut out = Vec::new();
        let stdin = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        run_check(
            stdin,
            Path::new("/definitely/not/a/path.yaml"),
            "test",
            &mut out,
        );
        let body = String::from_utf8(out).unwrap();
        assert!(body.contains("\"permissionDecision\":\"allow\""));
    }

    #[test]
    fn emit_approve_writes_modern_format() {
        let mut out = Vec::new();
        emit_approve(&mut out);
        let body = String::from_utf8(out).unwrap();
        assert!(body.contains("\"hookEventName\":\"PreToolUse\""));
        assert!(body.contains("\"permissionDecision\":\"allow\""));
    }

    // ── discover_workspace_root ──────────────────────────────────────────────

    #[test]
    fn discover_workspace_root_returns_dir_with_git_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join(".git")).expect("mk .git");
        let root = discover_workspace_root(dir.path());
        assert_eq!(root, dir.path());
    }

    #[test]
    fn discover_workspace_root_walks_up_from_subdirectory() {
        // The cwd-drift bug from 2026-05-22: an agent in
        // <repo>/crates/agent-guard-node trying to write <repo>/presets/...
        // saw the workspace bound stuck at the subdir and got
        // PATH_TRAVERSAL. With discovery, the bound climbs to the repo root.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join(".git")).expect("mk .git");
        let sub = dir.path().join("crates").join("agent-guard-node");
        std::fs::create_dir_all(&sub).expect("mk sub");
        let root = discover_workspace_root(&sub);
        assert_eq!(root, dir.path().to_path_buf());
    }

    #[test]
    fn discover_workspace_root_accepts_dot_git_as_file() {
        // Worktrees and submodules use a `.git` *file* with a `gitdir:`
        // redirect rather than a directory; the discovery has to accept
        // both shapes.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".git"), "gitdir: /elsewhere\n").expect("write .git file");
        let root = discover_workspace_root(dir.path());
        assert_eq!(root, dir.path());
    }

    #[test]
    fn discover_workspace_root_falls_back_to_cwd_when_no_git_ancestor() {
        // Outside any repo, behaviour is unchanged: return the cwd as-is so
        // existing non-git deployments keep their original workspace bound.
        let dir = tempfile::tempdir().expect("tempdir");
        let root = discover_workspace_root(dir.path());
        // The tempdir might itself be inside a git repo (e.g. /tmp on dev
        // machines), so we only assert that the returned path is an
        // ancestor of cwd — never a descendant or unrelated path.
        assert!(
            dir.path().starts_with(&root) || root == dir.path(),
            "expected discovery to land on cwd or an ancestor, got {root:?} for cwd {:?}",
            dir.path(),
        );
    }
}
