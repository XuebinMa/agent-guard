//! Bash command validation submodules.
//!
//! Ports the upstream `BashTool` validation pipeline:
//! - `readOnlyValidation` — block write-like commands in read-only mode
//! - `destructiveCommandWarning` — flag dangerous destructive commands
//! - `modeValidation` — enforce permission mode constraints on commands
//! - `sedValidation` — validate sed expressions before execution
//! - `pathValidation` — detect suspicious path patterns
//! - `commandSemantics` — classify command intent

use std::path::Path;

// Defined locally so this crate has no dependency on old `crate::permissions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionMode {
    ReadOnly,
    WorkspaceWrite,
    DangerFullAccess,
    Allow,
    Prompt,
}

/// Result of validating a bash command before execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// Command is safe to execute.
    Allow,
    /// Command should be blocked with the given reason.
    Block { reason: String },
    /// Command requires user confirmation with the given warning.
    Warn { message: String },
}

/// Semantic classification of a bash command's intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandIntent {
    ReadOnly,
    Write,
    Destructive,
    Network,
    ProcessManagement,
    PackageManagement,
    SystemAdmin,
    Unknown,
}

/// Bridge: run full validation pipeline and return a `GuardDecision`-compatible result.
pub fn validate_bash_command(
    command: &str,
    mode: PermissionMode,
    workspace: &Path,
) -> ValidationResult {
    validate_command(command, mode, workspace)
}

// ---------------------------------------------------------------------------
// readOnlyValidation
// ---------------------------------------------------------------------------

const WRITE_COMMANDS: &[&str] = &[
    "cp", "mv", "rm", "mkdir", "rmdir", "touch", "chmod", "chown", "chgrp", "ln", "install", "tee",
    "truncate", "shred", "mkfifo", "mknod", "dd",
];

const STATE_MODIFYING_COMMANDS: &[&str] = &[
    "apt", "apt-get", "yum", "dnf", "pacman", "brew", "pip", "pip3", "npm", "yarn", "pnpm",
    "bun", "cargo", "gem", "go", "rustup", "docker", "systemctl", "service", "mount", "umount",
    "kill", "pkill", "killall", "reboot", "shutdown", "halt", "poweroff", "useradd", "userdel",
    "usermod", "groupadd", "groupdel", "crontab", "at",
];

const WRITE_REDIRECTIONS: &[&str] = &[">", ">>", ">&"];

#[must_use]
pub fn validate_read_only(command: &str, mode: PermissionMode) -> ValidationResult {
    if mode != PermissionMode::ReadOnly {
        return ValidationResult::Allow;
    }

    let first_command = extract_first_command(command);

    for &write_cmd in WRITE_COMMANDS {
        if first_command == write_cmd {
            return ValidationResult::Block {
                reason: format!(
                    "Command '{write_cmd}' modifies the filesystem and is not allowed in read-only mode"
                ),
            };
        }
    }

    for &state_cmd in STATE_MODIFYING_COMMANDS {
        if first_command == state_cmd {
            return ValidationResult::Block {
                reason: format!(
                    "Command '{state_cmd}' modifies system state and is not allowed in read-only mode"
                ),
            };
        }
    }

    if first_command == "sudo" {
        let inner = extract_sudo_inner(command);
        if !inner.is_empty() {
            let inner_result = validate_read_only(inner, mode);
            if inner_result != ValidationResult::Allow {
                return inner_result;
            }
        }
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

    if first_command == "git" {
        return validate_git_read_only(command);
    }

    ValidationResult::Allow
}

const GIT_READ_ONLY_SUBCOMMANDS: &[&str] = &[
    "status", "log", "diff", "show", "branch", "tag", "stash", "remote", "fetch", "ls-files",
    "ls-tree", "cat-file", "rev-parse", "describe", "shortlog", "blame", "bisect", "reflog",
    "config",
];

fn validate_git_read_only(command: &str) -> ValidationResult {
    let parts: Vec<&str> = command.split_whitespace().collect();
    let subcommand = parts.iter().skip(1).find(|p| !p.starts_with('-'));
    match subcommand {
        Some(&sub) if GIT_READ_ONLY_SUBCOMMANDS.contains(&sub) => ValidationResult::Allow,
        Some(&sub) => ValidationResult::Block {
            reason: format!(
                "Git subcommand '{sub}' modifies repository state and is not allowed in read-only mode"
            ),
        },
        None => ValidationResult::Allow,
    }
}

// ---------------------------------------------------------------------------
// destructiveCommandWarning
// ---------------------------------------------------------------------------

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
    for &(pattern, warning) in DESTRUCTIVE_PATTERNS {
        if command.contains(pattern) {
            return ValidationResult::Warn {
                message: format!("Destructive command detected: {warning}"),
            };
        }
    }

    let first = extract_first_command(command);
    for &cmd in ALWAYS_DESTRUCTIVE_COMMANDS {
        if first == cmd {
            return ValidationResult::Warn {
                message: format!("Command '{cmd}' is inherently destructive and may cause data loss"),
            };
        }
    }

    if command.contains("rm ") && command.contains("-r") && command.contains("-f") {
        return ValidationResult::Warn {
            message: "Recursive forced deletion detected — verify the target path is correct"
                .to_string(),
        };
    }

    ValidationResult::Allow
}

// ---------------------------------------------------------------------------
// modeValidation
// ---------------------------------------------------------------------------

#[must_use]
pub fn validate_mode(command: &str, mode: PermissionMode) -> ValidationResult {
    match mode {
        PermissionMode::ReadOnly => validate_read_only(command, mode),
        PermissionMode::WorkspaceWrite => {
            if command_targets_outside_workspace(command) {
                return ValidationResult::Warn {
                    message: "Command appears to target files outside the workspace — requires elevated permission"
                        .to_string(),
                };
            }
            ValidationResult::Allow
        }
        PermissionMode::DangerFullAccess | PermissionMode::Allow | PermissionMode::Prompt => {
            ValidationResult::Allow
        }
    }
}

fn command_targets_outside_workspace(command: &str) -> bool {
    let system_paths = [
        "/etc/", "/usr/", "/var/", "/boot/", "/sys/", "/proc/", "/dev/", "/sbin/", "/lib/", "/opt/",
    ];

    let first = extract_first_command(command);
    let is_write_cmd = WRITE_COMMANDS.contains(&first.as_str())
        || STATE_MODIFYING_COMMANDS.contains(&first.as_str());

    if !is_write_cmd {
        return false;
    }

    for sys_path in &system_paths {
        if command.contains(sys_path) {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// sedValidation
// ---------------------------------------------------------------------------

#[must_use]
pub fn validate_sed(command: &str, mode: PermissionMode) -> ValidationResult {
    let first = extract_first_command(command);
    if first != "sed" {
        return ValidationResult::Allow;
    }

    if mode == PermissionMode::ReadOnly && command.contains(" -i") {
        return ValidationResult::Block {
            reason: "sed -i (in-place editing) is not allowed in read-only mode".to_string(),
        };
    }

    ValidationResult::Allow
}

// ---------------------------------------------------------------------------
// pathValidation
// ---------------------------------------------------------------------------

#[must_use]
pub fn validate_paths(command: &str, workspace: &Path) -> ValidationResult {
    if command.contains("../") {
        let workspace_str = workspace.to_string_lossy();
        if !command.contains(&*workspace_str) {
            return ValidationResult::Warn {
                message: "Command contains directory traversal pattern '../' — verify the target path resolves within the workspace".to_string(),
            };
        }
    }

    if command.contains("~/") || command.contains("$HOME") {
        return ValidationResult::Warn {
            message: "Command references home directory — verify it stays within the workspace scope"
                .to_string(),
        };
    }

    ValidationResult::Allow
}

// ---------------------------------------------------------------------------
// commandSemantics
// ---------------------------------------------------------------------------

const SEMANTIC_READ_ONLY_COMMANDS: &[&str] = &[
    "ls", "cat", "head", "tail", "less", "more", "wc", "sort", "uniq", "grep", "egrep", "fgrep",
    "find", "which", "whereis", "whatis", "man", "info", "file", "stat", "du", "df", "free",
    "uptime", "uname", "hostname", "whoami", "id", "groups", "env", "printenv", "echo", "printf",
    "date", "cal", "bc", "expr", "test", "true", "false", "pwd", "tree", "diff", "cmp", "md5sum",
    "sha256sum", "sha1sum", "xxd", "od", "hexdump", "strings", "readlink", "realpath", "basename",
    "dirname", "seq", "yes", "tput", "column", "jq", "yq", "xargs", "tr", "cut", "paste", "awk",
    "sed",
];

const NETWORK_COMMANDS: &[&str] = &[
    "curl", "wget", "ssh", "scp", "rsync", "ftp", "sftp", "nc", "ncat", "telnet", "ping",
    "traceroute", "dig", "nslookup", "host", "whois", "ifconfig", "ip", "netstat", "ss", "nmap",
];

const PROCESS_COMMANDS: &[&str] = &[
    "kill", "pkill", "killall", "ps", "top", "htop", "bg", "fg", "jobs", "nohup", "disown",
    "wait", "nice", "renice",
];

const PACKAGE_COMMANDS: &[&str] = &[
    "apt", "apt-get", "yum", "dnf", "pacman", "brew", "pip", "pip3", "npm", "yarn", "pnpm",
    "bun", "cargo", "gem", "go", "rustup", "snap", "flatpak",
];

const SYSTEM_ADMIN_COMMANDS: &[&str] = &[
    "sudo", "su", "chroot", "mount", "umount", "fdisk", "parted", "lsblk", "blkid", "systemctl",
    "service", "journalctl", "dmesg", "modprobe", "insmod", "rmmod", "iptables", "ufw",
    "firewall-cmd", "sysctl", "crontab", "at", "useradd", "userdel", "usermod", "groupadd",
    "groupdel", "passwd", "visudo",
];

#[must_use]
pub fn classify_intent(command: &str) -> CommandIntent {
    let first = extract_first_command(command);
    classify_by_first_command(&first, command)
}

fn classify_by_first_command(first: &str, command: &str) -> CommandIntent {
    if SEMANTIC_READ_ONLY_COMMANDS.contains(&first) {
        if first == "sed" && command.contains(" -i") {
            return CommandIntent::Write;
        }
        return CommandIntent::ReadOnly;
    }

    if ALWAYS_DESTRUCTIVE_COMMANDS.contains(&first) || first == "rm" {
        return CommandIntent::Destructive;
    }

    if WRITE_COMMANDS.contains(&first) {
        return CommandIntent::Write;
    }

    if NETWORK_COMMANDS.contains(&first) {
        return CommandIntent::Network;
    }

    if PROCESS_COMMANDS.contains(&first) {
        return CommandIntent::ProcessManagement;
    }

    if PACKAGE_COMMANDS.contains(&first) {
        return CommandIntent::PackageManagement;
    }

    if SYSTEM_ADMIN_COMMANDS.contains(&first) {
        return CommandIntent::SystemAdmin;
    }

    if first == "git" {
        return classify_git_command(command);
    }

    CommandIntent::Unknown
}

fn classify_git_command(command: &str) -> CommandIntent {
    let parts: Vec<&str> = command.split_whitespace().collect();
    let subcommand = parts.iter().skip(1).find(|p| !p.starts_with('-'));
    match subcommand {
        Some(&sub) if GIT_READ_ONLY_SUBCOMMANDS.contains(&sub) => CommandIntent::ReadOnly,
        _ => CommandIntent::Write,
    }
}

// ---------------------------------------------------------------------------
// Full pipeline
// ---------------------------------------------------------------------------

#[must_use]
pub fn validate_command(command: &str, mode: PermissionMode, workspace: &Path) -> ValidationResult {
    let result = validate_mode(command, mode);
    if result != ValidationResult::Allow {
        return result;
    }

    let result = validate_sed(command, mode);
    if result != ValidationResult::Allow {
        return result;
    }

    let result = check_destructive(command);
    if result != ValidationResult::Allow {
        return result;
    }

    validate_paths(command, workspace)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn extract_first_command(command: &str) -> String {
    let trimmed = command.trim();
    let mut remaining = trimmed;
    loop {
        let next = remaining.trim_start();
        if let Some(eq_pos) = next.find('=') {
            let before_eq = &next[..eq_pos];
            if !before_eq.is_empty()
                && before_eq.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                let after_eq = &next[eq_pos + 1..];
                if let Some(space) = find_end_of_value(after_eq) {
                    remaining = &after_eq[space..];
                    continue;
                }
                return String::new();
            }
        }
        break;
    }

    remaining
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string()
}

fn extract_sudo_inner(command: &str) -> &str {
    let parts: Vec<&str> = command.split_whitespace().collect();
    let sudo_idx = parts.iter().position(|&p| p == "sudo");
    match sudo_idx {
        Some(idx) => {
            let rest = &parts[idx + 1..];
            for &part in rest {
                if !part.starts_with('-') {
                    let offset = command.find(part).unwrap_or(0);
                    return &command[offset..];
                }
            }
            ""
        }
        None => "",
    }
}

fn find_end_of_value(s: &str) -> Option<usize> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }

    let first = s.as_bytes()[0];
    if first == b'"' || first == b'\'' {
        let quote = first;
        let mut i = 1;
        while i < s.len() {
            if s.as_bytes()[i] == quote && (i == 0 || s.as_bytes()[i - 1] != b'\\') {
                i += 1;
                while i < s.len() && !s.as_bytes()[i].is_ascii_whitespace() {
                    i += 1;
                }
                return if i < s.len() { Some(i) } else { None };
            }
            i += 1;
        }
        None
    } else {
        s.find(char::is_whitespace)
    }
}
