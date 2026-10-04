//! Read-only mode validation: rejects filesystem/state-mutating commands.

use super::ast::{environment_writes, parse_shell, ShellParse};
use super::tables::{
    is_code_execution_env_var, DANGEROUS_ENV_VAR_PREFIXES, READ_ONLY_COMMANDS,
    STATE_MODIFYING_COMMANDS, WRITE_COMMANDS, WRITE_REDIRECTIONS,
};
use super::tokenize::shell_split;
use super::types::{PermissionMode, ValidationResult};
use super::wrappers::{command_name, unwrap_command_wrappers};

#[must_use]
pub fn validate_read_only(command: &str, mode: PermissionMode) -> ValidationResult {
    if mode != PermissionMode::ReadOnly {
        return ValidationResult::Allow;
    }

    // Industrial Standard Mitigation: Proper shell splitting that respects quotes
    let parts = shell_split(command);

    // Token-prefix scan for dangerous env-var assignments. Runs over the
    // post-quote-strip tokens, so quoting tricks (`L'D'_PRELOAD=...`) are
    // caught and benign filename matches are not. This also sees the
    // `env NAME=value cmd` form, where the assignment is an argument to `env`
    // rather than a shell variable_assignment node.
    for token in &parts {
        for &prefix in DANGEROUS_ENV_VAR_PREFIXES {
            if token.starts_with(prefix) {
                return ValidationResult::Block {
                    reason: format!(
                        "Environment variable injection attempt detected ({}…)",
                        prefix.trim_end_matches('=')
                    ),
                };
            }
        }
        if let Some((name, _)) = token.split_once('=') {
            if is_code_execution_env_var(name) {
                return ValidationResult::Block {
                    reason: format!(
                        "Environment variable {name} names a program a later command would \
                         execute and is not allowed in read-only mode"
                    ),
                };
            }
        }
    }

    // The raw-token scan above misses assignments that only the grammar
    // recovers: `export NAME=...`, a statement-level `NAME=...;`, and the
    // `${NAME:=value}` default-assignment form. Consult the parsed environment
    // writes so those spellings cannot reach a code-execution variable either.
    for write in environment_writes(command) {
        if is_code_execution_env_var(&write.name) {
            return ValidationResult::Block {
                reason: format!(
                    "Environment variable {} names a program a later command would \
                     execute and is not allowed in read-only mode",
                    write.name
                ),
            };
        }
    }

    // Command positions come from the grammar, not from splitting on
    // `| ; && || &`. A flat split makes `{`, `then`, and `do` look like the
    // command word, which hid every command nested inside a grouping
    // construct from the checks below.
    match parse_shell(command) {
        ShellParse::TooComplex(reason) => {
            return ValidationResult::Block {
                reason: format!("Command cannot be validated in read-only mode: {reason}"),
            };
        }
        ShellParse::Understood(commands) => {
            for resolved in &commands {
                if let Some(res) = check_command_segment(&resolved.argv) {
                    return res;
                }
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

    ValidationResult::Allow
}

fn check_command_segment(parts: &[String]) -> Option<ValidationResult> {
    if parts.is_empty() {
        return None;
    }

    // Detect process substitution (CWE-78) over the full, un-unwrapped segment.
    for part in parts {
        if part.contains("<(") || part.contains(">(") {
            return Some(ValidationResult::Block {
                reason: "Shell process substitution is not allowed in read-only mode".to_string(),
            });
        }
    }

    // Strip transparent wrappers (`sudo`/`env`/`nice`/`nohup`/`timeout`/`doas`)
    // and `NAME=value` prefixes so the *real* command word — not a wrapper flag
    // or operand — drives the checks below. Without this, `sudo -u root rm`,
    // `env FOO=1 rm`, or `FOO=1 rm` hid the destructive command from this gate
    // (audit 2026-05-18 / 2026-05-19 / 2026-06-08).
    let parts = unwrap_command_wrappers(parts);
    let first_command = command_name(parts.first()?);

    if first_command == "git" {
        let Some(subcommand) = git_subcommand(parts) else {
            return Some(ValidationResult::Block {
                reason: "Git invocation cannot be proven read-only".to_string(),
            });
        };
        const READ_ONLY_GIT_SUBCOMMANDS: &[&str] = &[
            "annotate",
            "blame",
            "cat-file",
            "diff",
            "diff-files",
            "diff-index",
            "diff-tree",
            "for-each-ref",
            "grep",
            "log",
            "ls-files",
            "ls-remote",
            "ls-tree",
            "merge-base",
            "name-rev",
            "rev-list",
            "rev-parse",
            "show",
            "show-ref",
            "status",
            "verify-commit",
            "verify-tag",
        ];
        if READ_ONLY_GIT_SUBCOMMANDS.contains(&subcommand) {
            return None;
        }
        return Some(ValidationResult::Block {
            reason: format!(
                "Git command '{subcommand}' is not proven read-only and is not allowed in read-only mode"
            ),
        });
    }

    if first_command == "git-send-pack" {
        return Some(ValidationResult::Block {
            reason: "Git command 'send-pack' modifies a remote repository and is not allowed in read-only mode"
                .to_string(),
        });
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
        // A script read from a file is opaque executable text, exactly like
        // `python3 script.py`: it may carry `w`/`e`/`r` commands that write,
        // execute, or read outside the workspace, so it cannot be proven
        // read-only.
        if parts
            .iter()
            .any(|p| p == "-f" || p == "--file" || p.starts_with("--file="))
        {
            return Some(ValidationResult::Block {
                reason: "Sed with a script file (-f) cannot be proven read-only".to_string(),
            });
        }
        return None;
    }

    if first_command == "rg" || first_command == "ripgrep" {
        // `--pre` runs a preprocessor program for every searched file, and
        // `--hostname-bin` runs a program to resolve the hostname. Either turns
        // an allow-listed search into arbitrary execution.
        if parts.iter().any(|p| {
            matches!(p.as_str(), "--pre" | "--hostname-bin")
                || p.starts_with("--pre=")
                || p.starts_with("--hostname-bin=")
        }) {
            return Some(ValidationResult::Block {
                reason: "ripgrep is invoked with a flag that runs an external program and is not allowed in read-only mode"
                    .to_string(),
            });
        }
        return None;
    }

    if first_command == "find" {
        const WRITE_ACTIONS: &[&str] = &[
            "-delete", "-fls", "-fprint", "-fprint0", "-fprintf", "-ok", "-okdir",
        ];
        if parts
            .iter()
            .any(|argument| WRITE_ACTIONS.contains(&argument.as_str()))
        {
            return Some(ValidationResult::Block {
                reason: "Find invocation contains an action that is not read-only".to_string(),
            });
        }
        return None;
    }

    if is_interpreter_metadata_query(first_command, &parts[1..]) {
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

    if !READ_ONLY_COMMANDS.contains(&first_command) {
        return Some(ValidationResult::Block {
            reason: format!(
                "Command '{first_command}' is not in the read-only executable allowlist"
            ),
        });
    }

    // Wrapper layers (`sudo`/`env`/…) are stripped up front by
    // `unwrap_command_wrappers`, so `first_command` is already the real command.

    // Interpreter-laundering check lives in `validate_bash_command`'s
    // early gate (see `contains_interpreter_with_inline_code`); it now
    // covers both ReadOnly and WorkspaceWrite modes, so no per-segment
    // check is needed here.

    None
}

fn is_interpreter_metadata_query(command: &str, arguments: &[String]) -> bool {
    const INTERPRETERS: &[&str] = &[
        "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php", "sh", "bash",
        "zsh", "ksh", "dash", "fish",
    ];
    INTERPRETERS.contains(&command)
        && !arguments.is_empty()
        && arguments
            .iter()
            .all(|argument| matches!(argument.as_str(), "--version" | "-V" | "--help" | "-h"))
}

/// Resolve a Git subcommand without mistaking a global option operand for the
/// command. Unknown global option grammar fails closed by returning `None`.
fn git_subcommand(parts: &[String]) -> Option<&str> {
    let mut index = 1;
    while index < parts.len() {
        let argument = parts[index].as_str();
        if argument == "--" {
            return parts.get(index + 1).map(String::as_str);
        }
        if matches!(argument, "-C" | "--git-dir" | "--work-tree" | "--namespace") {
            index += 2;
            continue;
        }
        if argument.starts_with("--git-dir=")
            || argument.starts_with("--work-tree=")
            || argument.starts_with("--namespace=")
            || (argument.starts_with("-C") && argument.len() > 2)
        {
            index += 1;
            continue;
        }
        if matches!(
            argument,
            "--no-pager"
                | "--paginate"
                | "-p"
                | "--no-optional-locks"
                | "--literal-pathspecs"
                | "--glob-pathspecs"
                | "--noglob-pathspecs"
                | "--icase-pathspecs"
        ) {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            return None;
        }
        return Some(argument);
    }
    None
}
