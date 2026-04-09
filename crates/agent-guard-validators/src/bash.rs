//! Bash command validation submodules.

use std::path::Path;

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
    Read,
    Write,
    Execute,
    System,
    Unknown,
}

// ── Read-only Validation ─────────────────────────────────────────────────────

const WRITE_COMMANDS: &[&str] = &[
    "rm", "mv", "cp", "touch", "mkdir", "rmdir", "chmod", "chown", "chgrp", "ln", "link", "unlink",
    "dd", "mkfs", "mount", "umount", "tar", "zip", "unzip", "gzip", "gunzip", "bzip2", "bunzip2",
    "7z", "xz", "unxz", "tee", "git", "apt", "yum", "dnf", "npm", "pip", "pip3", "cargo",
];

const STATE_MODIFYING_COMMANDS: &[&str] = &[
    "kill", "pkill", "killall", "service", "systemctl", "shutdown", "reboot", "sudo", "su",
];

const WRITE_REDIRECTIONS: &[&str] = &[">", ">>", ">&", "<", "<<", "<<<"];

#[must_use]
pub fn validate_read_only(command: &str, mode: PermissionMode) -> ValidationResult {
    if mode != PermissionMode::ReadOnly {
        return ValidationResult::Allow;
    }

    // Industrial Standard Mitigation: Detect environment variable injections (CWE-94)
    if command.contains("LD_PRELOAD") || command.contains("PYTHONPATH") || command.contains("NODE_OPTIONS") {
         return ValidationResult::Block {
            reason: "Environment variable injection attempt detected".to_string(),
        };
    }

    // Industrial Standard Mitigation: Proper shell splitting that respects quotes
    let parts = shell_split(command);
    
    let mut current_cmd_parts = Vec::new();
    for part in parts {
        if part == "|" || part == ";" || part == "&" || part == "&&" || part == "||" {
            if let Some(res) = check_command_segment(&current_cmd_parts, mode) {
                return res;
            }
            current_cmd_parts.clear();
        } else {
            current_cmd_parts.push(part);
        }
    }
    
    if let Some(res) = check_command_segment(&current_cmd_parts, mode) {
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

fn check_command_segment(parts: &[String], _mode: PermissionMode) -> Option<ValidationResult> {
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

    if first_command == "sudo" {
        if parts.len() > 1 {
            let inner = parts[1..].to_vec();
            return check_command_segment(&inner, _mode);
        }
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

    for c in s.chars() {
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
    ("rm -rf /", "Recursive forced deletion at root — this will destroy the system"),
    ("rm -rf ~", "Recursive forced deletion of home directory"),
    ("rm -rf *", "Recursive forced deletion of all files in current directory"),
    ("rm -rf .", "Recursive forced deletion of current directory"),
    ("mkfs", "Filesystem creation will destroy existing data on the device"),
    ("dd if=", "Direct disk write — can overwrite partitions or devices"),
    ("> /dev/sd", "Writing to raw disk device"),
    ("chmod -R 777", "Recursively setting world-writable permissions"),
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
    s.split_whitespace()
        .next()
        .unwrap_or("")
        .to_string()
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

    check_destructive(command)
}

pub fn classify_intent(_command: &str) -> CommandIntent {
    CommandIntent::Unknown
}

pub fn validate_command(command: &str, mode: PermissionMode, _workspace: &Path) -> ValidationResult {
    validate_bash_command(command, mode, _workspace)
}

pub fn validate_mode(command: &str, mode: PermissionMode) -> ValidationResult {
    validate_read_only(command, mode)
}

pub fn validate_paths(_command: &str, _mode: PermissionMode, _workspace: &Path) -> ValidationResult {
    ValidationResult::Allow
}

pub fn validate_sed(_command: &str, _mode: PermissionMode) -> ValidationResult {
    ValidationResult::Allow
}
