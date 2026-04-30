//! Bash command validation submodules.

use std::path::{Component, Path, PathBuf};

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionMode {
    Blocked,
    ReadOnly,
    WorkspaceWrite,
    DangerFullAccess,
    Allow,
    Prompt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    Allow,
    Block { reason: String },
    Warn { message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandIntent {
    ReadOnly,
    Write,
    Execute,
    Network,
    PackageManagement,
    SystemAdmin,
    Destructive,
    Unknown,
}

// ── Read-only Validation ─────────────────────────────────────────────────────

const WRITE_COMMANDS: &[&str] = &[
    "rm", "mv", "cp", "touch", "mkdir", "rmdir", "chmod", "chown", "chgrp", "ln", "link", "unlink",
    "dd", "mkfs", "mount", "umount", "tar", "zip", "unzip", "gzip", "gunzip", "bzip2", "bunzip2",
    "7z", "xz", "unxz", "tee", "apt", "apt-get", "yum", "dnf", "npm", "pip", "pip3", "cargo",
];

const STATE_MODIFYING_COMMANDS: &[&str] = &[
    "kill",
    "pkill",
    "killall",
    "service",
    "systemctl",
    "shutdown",
    "reboot",
    "su",
];

const WRITE_REDIRECTIONS: &[&str] = &[">", ">>", ">&"];

/// Redirections that consume the next token as a filesystem path.
const READ_PATH_REDIRECTIONS: &[&str] = &["<"];

/// Read-side redirections whose target is data, not a path. Listed here
/// only so the tokenizer doesn't misclassify them; they do not yield
/// path-validation targets.
///
/// `<<`  — here-doc; the next token is a delimiter word, not a file.
/// `<<<` — here-string; the next token is the literal string content.
#[allow(dead_code)]
const READ_DATA_REDIRECTIONS: &[&str] = &["<<", "<<<"];

#[must_use]
pub fn validate_read_only(command: &str, mode: PermissionMode) -> ValidationResult {
    if mode != PermissionMode::ReadOnly {
        return ValidationResult::Allow;
    }

    // Industrial Standard Mitigation: Detect environment variable injections (CWE-94)
    if command.contains("LD_PRELOAD")
        || command.contains("PYTHONPATH")
        || command.contains("NODE_OPTIONS")
    {
        return ValidationResult::Block {
            reason: "Environment variable injection attempt detected".to_string(),
        };
    }

    // Industrial Standard Mitigation: Proper shell splitting that respects quotes
    let parts = shell_split(command);

    let mut current_cmd_parts = Vec::new();
    for part in parts {
        if part == "|" || part == ";" || part == "&&" || part == "||" || part == "&" {
            if let Some(res) = check_command_segment(&current_cmd_parts) {
                return res;
            }
            current_cmd_parts.clear();
        } else {
            current_cmd_parts.push(part);
        }
    }

    if let Some(res) = check_command_segment(&current_cmd_parts) {
        return res;
    }

    for &redir in WRITE_REDIRECTIONS {
        if command.contains(redir) {
            return ValidationResult::Block {
                reason: format!(
                    "Command contains write redirection '{redir}' which is not allowed in read-only mode"
                ),
            };
        }
    }

    ValidationResult::Allow
}

fn check_command_segment(parts: &[String]) -> Option<ValidationResult> {
    if parts.is_empty() {
        return None;
    }

    let first_command = &parts[0];

    // Detect process substitution (CWE-78)
    for part in parts {
        if part.contains("<(") || part.contains(">(") {
            return Some(ValidationResult::Block {
                reason: "Shell process substitution is not allowed in read-only mode".to_string(),
            });
        }
    }

    if first_command == "git" {
        if parts.len() > 1 {
            let sub = &parts[1];
            let write_subs = [
                "commit", "push", "pull", "merge", "checkout", "add", "rebase", "reset", "init",
            ];
            if write_subs.contains(&sub.as_str()) {
                return Some(ValidationResult::Block {
                    reason: format!("Git command '{sub}' modifies the repository and is not allowed in read-only mode"),
                });
            }
        }
        return None;
    }

    if first_command == "sed" {
        if parts
            .iter()
            .any(|p| p == "-i" || p.starts_with("--in-place"))
        {
            return Some(ValidationResult::Block {
                reason: "Sed in-place editing is not allowed in read-only mode".to_string(),
            });
        }
        return None;
    }

    for &write_cmd in WRITE_COMMANDS {
        if first_command == write_cmd {
            return Some(ValidationResult::Block {
                reason: format!(
                    "Command '{write_cmd}' modifies the filesystem and is not allowed in read-only mode"
                ),
            });
        }
    }

    for &state_cmd in STATE_MODIFYING_COMMANDS {
        if first_command == state_cmd {
            return Some(ValidationResult::Block {
                reason: format!(
                    "Command '{state_cmd}' modifies system state and is not allowed in read-only mode"
                ),
            });
        }
    }

    if first_command == "sudo" && parts.len() > 1 {
        let inner = parts[1..].to_vec();
        return check_command_segment(&inner);
    }

    None
}

/// Simple shell splitter that respects single and double quotes.
fn shell_split(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escaped = false;
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }

        match c {
            '\\' if !in_single_quote => escaped = true,
            '\'' if !in_double_quote => in_single_quote = !in_single_quote,
            '"' if !in_single_quote => in_double_quote = !in_double_quote,
            ' ' | '\t' | '\n' | '\r' if !in_single_quote && !in_double_quote => {
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
            }
            '|' | ';' | '&' if !in_single_quote && !in_double_quote => {
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
                if matches!(c, '&' | '|') && chars.peek() == Some(&c) {
                    let _ = chars.next();
                    parts.push(format!("{c}{c}"));
                    continue;
                }
                parts.push(c.to_string());
            }
            _ => current.push(c),
        }
    }

    if !current.is_empty() {
        parts.push(current);
    }

    parts
}

// ── Destructive Command Warning ──────────────────────────────────────────────

const DESTRUCTIVE_PATTERNS: &[(&str, &str)] = &[
    (
        "rm -rf /",
        "Recursive forced deletion at root — this will destroy the system",
    ),
    ("rm -rf ~", "Recursive forced deletion of home directory"),
    (
        "rm -rf *",
        "Recursive forced deletion of all files in current directory",
    ),
    ("rm -rf .", "Recursive forced deletion of current directory"),
    (
        "mkfs",
        "Filesystem creation will destroy existing data on the device",
    ),
    (
        "dd if=",
        "Direct disk write — can overwrite partitions or devices",
    ),
    ("> /dev/sd", "Writing to raw disk device"),
    (
        "chmod -R 777",
        "Recursively setting world-writable permissions",
    ),
    ("chmod -R 000", "Recursively removing all permissions"),
    (":(){ :|:& };:", "Fork bomb — will crash the system"),
];

const ALWAYS_DESTRUCTIVE_COMMANDS: &[&str] = &["shred", "wipefs"];

#[must_use]
pub fn check_destructive(command: &str) -> ValidationResult {
    let normalized = command.to_lowercase();
    for (pattern, message) in DESTRUCTIVE_PATTERNS {
        if normalized.contains(pattern) {
            return ValidationResult::Warn {
                message: message.to_string(),
            };
        }
    }

    let first = extract_first_command(command);
    if ALWAYS_DESTRUCTIVE_COMMANDS.contains(&&*first) {
        return ValidationResult::Warn {
            message: format!("Command '{first}' is inherently destructive and dangerous"),
        };
    }

    ValidationResult::Allow
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn extract_first_command(s: &str) -> String {
    s.split_whitespace().next().unwrap_or("").to_string()
}

pub fn validate_bash_command(
    command: &str,
    mode: PermissionMode,
    workspace_path: &Path,
) -> ValidationResult {
    if mode == PermissionMode::Blocked {
        return ValidationResult::Block {
            reason: "tool is in blocked mode".to_string(),
        };
    }
    if mode == PermissionMode::Allow {
        return ValidationResult::Allow;
    }

    let res = validate_read_only(command, mode);
    if res != ValidationResult::Allow {
        return res;
    }

    let res = validate_paths(command, mode, workspace_path);
    if res != ValidationResult::Allow {
        return res;
    }

    check_destructive(command)
}

pub fn classify_intent(command: &str) -> CommandIntent {
    let first = extract_first_command(command);
    match first.as_str() {
        "ls" | "cat" | "pwd" | "git" => {
            if command.contains("push")
                || command.contains("commit")
                || command.contains("checkout")
            {
                CommandIntent::Write
            } else {
                CommandIntent::ReadOnly
            }
        }
        "rm" | "mkfs" | "dd" => CommandIntent::Destructive,
        "cp" | "mv" | "touch" | "sed" => CommandIntent::Write,
        "curl" | "wget" | "ping" => CommandIntent::Network,
        "npm" | "pip" | "apt" | "apt-get" | "yum" => CommandIntent::PackageManagement,
        "sudo" | "su" | "systemctl" => CommandIntent::SystemAdmin,
        _ => CommandIntent::Unknown,
    }
}

pub fn validate_command(
    command: &str,
    mode: PermissionMode,
    _workspace: &Path,
) -> ValidationResult {
    validate_bash_command(command, mode, _workspace)
}

pub fn validate_mode(command: &str, mode: PermissionMode) -> ValidationResult {
    validate_read_only(command, mode)
}

pub fn validate_paths(command: &str, mode: PermissionMode, workspace: &Path) -> ValidationResult {
    if !matches!(
        mode,
        PermissionMode::ReadOnly | PermissionMode::WorkspaceWrite
    ) {
        return ValidationResult::Allow;
    }

    let workspace = normalize_path(workspace);
    for target in collect_write_targets(command) {
        let candidate = target.trim_matches(|c| c == '"' || c == '\'');
        if candidate.is_empty() || candidate.starts_with('$') || candidate == "/dev/null" {
            continue;
        }

        let path = Path::new(candidate);
        if path.is_absolute() && !path_stays_within_workspace(path, &workspace) {
            return ValidationResult::Block {
                reason: format!(
                    "write target '{}' is outside the configured workspace",
                    candidate
                ),
            };
        }

        if !path.is_absolute() && has_parent_dir_escape(path) {
            return ValidationResult::Block {
                reason: format!(
                    "write target '{}' escapes the configured workspace",
                    candidate
                ),
            };
        }
    }

    for target in collect_read_targets(command) {
        let candidate = target.trim_matches(|c| c == '"' || c == '\'');
        if candidate.is_empty() || candidate.starts_with('$') || candidate == "/dev/null" {
            continue;
        }

        let path = Path::new(candidate);
        if path.is_absolute() && !path_stays_within_workspace(path, &workspace) {
            return ValidationResult::Block {
                reason: format!(
                    "read target '{}' is outside the configured workspace",
                    candidate
                ),
            };
        }

        if !path.is_absolute() && has_parent_dir_escape(path) {
            return ValidationResult::Block {
                reason: format!(
                    "read target '{}' escapes the configured workspace",
                    candidate
                ),
            };
        }
    }

    ValidationResult::Allow
}

pub fn validate_sed(command: &str, mode: PermissionMode) -> ValidationResult {
    if mode == PermissionMode::ReadOnly
        && (command.contains("-i") || command.contains("--in-place"))
    {
        return ValidationResult::Block {
            reason: "Sed in-place editing is not allowed in read-only mode".to_string(),
        };
    }
    ValidationResult::Allow
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn has_parent_dir_escape(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

fn path_stays_within_workspace(path: &Path, workspace: &Path) -> bool {
    let normalized_path = normalize_path(path);
    normalized_path == workspace || normalized_path.starts_with(workspace)
}

fn collect_write_targets(command: &str) -> Vec<String> {
    let tokens = shell_split(command);
    let mut targets = Vec::new();
    let mut current_segment = Vec::new();

    for token in tokens {
        if matches!(token.as_str(), "|" | "||" | "&&" | ";" | "&") {
            targets.extend(write_targets_for_segment(&current_segment));
            current_segment.clear();
            continue;
        }
        current_segment.push(token);
    }

    targets.extend(write_targets_for_segment(&current_segment));
    targets
}

fn write_targets_for_segment(segment: &[String]) -> Vec<String> {
    if segment.is_empty() {
        return Vec::new();
    }

    let mut targets = Vec::new();
    let mut command_index = 0;
    if segment.first().is_some_and(|token| token == "sudo") && segment.len() > 1 {
        command_index = 1;
    }

    let command = segment[command_index].as_str();
    let args = &segment[command_index + 1..];

    let mut expecting_redirection_target = false;
    for token in args {
        if WRITE_REDIRECTIONS.contains(&token.as_str()) {
            expecting_redirection_target = true;
            continue;
        }

        if expecting_redirection_target {
            expecting_redirection_target = false;
            if !token.starts_with('&') {
                targets.push(token.clone());
            }
        }
    }

    match command {
        "touch" | "mkdir" | "rmdir" | "rm" | "chmod" | "chown" | "chgrp" | "unlink" | "tee" => {
            targets.extend(
                args.iter()
                    .filter(|token| {
                        !token.starts_with('-') && !WRITE_REDIRECTIONS.contains(&token.as_str())
                    })
                    .cloned(),
            );
        }
        "mv" | "cp" | "ln" | "link" => {
            if let Some(last) = args.iter().rev().find(|token| {
                !token.starts_with('-') && !WRITE_REDIRECTIONS.contains(&token.as_str())
            }) {
                targets.push(last.clone());
            }
        }
        _ => {}
    }

    targets
}

fn collect_read_targets(command: &str) -> Vec<String> {
    let tokens = shell_split(command);
    let mut targets = Vec::new();
    let mut current_segment = Vec::new();

    for token in tokens {
        if matches!(token.as_str(), "|" | "||" | "&&" | ";" | "&") {
            targets.extend(read_targets_for_segment(&current_segment));
            current_segment.clear();
            continue;
        }
        current_segment.push(token);
    }

    targets.extend(read_targets_for_segment(&current_segment));
    targets
}

fn read_targets_for_segment(segment: &[String]) -> Vec<String> {
    if segment.is_empty() {
        return Vec::new();
    }

    let mut targets = Vec::new();
    let mut command_index = 0;
    if segment.first().is_some_and(|token| token == "sudo") && segment.len() > 1 {
        command_index = 1;
    }

    let args = &segment[command_index + 1..];

    // Only explicit `<` redirections are treated as path targets.
    // `<<` (here-doc) and `<<<` (here-string) are tokenized as single tokens
    // by `shell_split` (which doesn't split on `<`/`>`), so an exact-match on
    // `READ_PATH_REDIRECTIONS` (just `<`) naturally excludes them. We do not
    // infer read targets from positional args (e.g. `cat /etc/shadow`) — that
    // is out of scope and covered by the `read_file` tool path with deny lists.
    let mut expecting_redirection_target = false;
    for token in args {
        if READ_PATH_REDIRECTIONS.contains(&token.as_str()) {
            expecting_redirection_target = true;
            continue;
        }

        if expecting_redirection_target {
            expecting_redirection_target = false;
            if !token.starts_with('&') {
                targets.push(token.clone());
            }
        }
    }

    targets
}

#[cfg(test)]
mod tests {
    use super::{
        shell_split, validate_paths, validate_read_only, PermissionMode, ValidationResult,
    };
    use std::path::Path;

    #[test]
    fn shell_split_keeps_boolean_operators_together() {
        let parts = shell_split("echo one && echo two || echo three");
        assert_eq!(
            parts,
            vec!["echo", "one", "&&", "echo", "two", "||", "echo", "three"]
        );
    }

    #[test]
    fn shell_split_respects_quotes_around_operators() {
        let parts = shell_split(r#"echo "a && b" && echo 'c || d'"#);
        assert_eq!(parts, vec!["echo", "a && b", "&&", "echo", "c || d"]);
    }

    #[test]
    fn read_only_allows_input_redirection() {
        let result = validate_read_only("cat < input.txt", PermissionMode::ReadOnly);
        assert_eq!(result, ValidationResult::Allow);
    }

    #[test]
    fn validate_paths_allows_workspace_relative_write() {
        let result = validate_paths(
            "echo ok > output.txt",
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
        );
        assert_eq!(result, ValidationResult::Allow);
    }

    #[test]
    fn validate_paths_blocks_absolute_path_outside_workspace() {
        let result = validate_paths(
            "echo ok > /etc/passwd",
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
        );
        assert!(matches!(result, ValidationResult::Block { .. }));
    }

    #[test]
    fn validate_paths_blocks_parent_dir_escape() {
        let result = validate_paths(
            "echo ok > ../outside.txt",
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
        );
        assert!(matches!(result, ValidationResult::Block { .. }));
    }

    #[test]
    fn validate_paths_blocks_common_write_command_outside_workspace() {
        let result = validate_paths(
            "tee /etc/passwd",
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
        );
        assert!(matches!(result, ValidationResult::Block { .. }));
    }
}
