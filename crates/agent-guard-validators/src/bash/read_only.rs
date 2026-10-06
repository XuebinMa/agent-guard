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
    // caught and benign filename matches are not. This also covers `env`
    // assignments, which are arguments rather than variable_assignment nodes.
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
                        "Environment variable {name} can configure an uninspected program and is not allowed in read-only mode"
                    ),
                };
            }
        }
    }

    // Declaration arguments and parameter assignments are recovered from the
    // grammar as well: they need not occur in an ordinary command argv.
    for write in environment_writes(command) {
        if is_code_execution_env_var(&write.name) {
            return ValidationResult::Block {
                reason: format!(
                    "Environment variable {} can configure an uninspected program and is not allowed in read-only mode",
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

    // The grammar has decoded quotes and ANSI-C words here. Only the removed
    // wrapper prefix carries environment assignments; the real command's
    // operands may contain identical literal data (for example in `echo`).
    let unwrapped = unwrap_command_wrappers(parts);
    // `find -exec` may truncate the child at its terminator, so the returned
    // slice is not necessarily a suffix. Locate its start rather than infer
    // the prefix from the two slice lengths.
    let prefix_len = parts
        .iter()
        .position(|token| std::ptr::eq(token, unwrapped.as_ptr()))
        .unwrap_or(parts.len());
    for token in &parts[..prefix_len] {
        if let Some((name, _)) = token.split_once('=') {
            if is_code_execution_env_var(name) {
                return Some(ValidationResult::Block {
                    reason: format!(
                        "Environment variable {name} can configure an uninspected program and is not allowed in read-only mode"
                    ),
                });
            }
        }
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
    let parts = unwrapped;
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
            return git_option_that_writes_or_executes(parts).map(|option| {
                ValidationResult::Block {
                    reason: format!(
                        "Git option '{option}' writes a file or runs a program and is not allowed in read-only mode"
                    ),
                }
            });
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
        return match super::sed::parse(&parts[1..]) {
            Ok(invocation) if invocation.in_place => Some(ValidationResult::Block {
                reason: "Sed in-place editing is not allowed in read-only mode".to_string(),
            }),
            Ok(_) => None,
            Err(reason) => Some(ValidationResult::Block {
                reason: reason.to_string(),
            }),
        };
    }

    if first_command == "rg" || first_command == "ripgrep" {
        return super::ripgrep::validate_arguments(&parts[1..])
            .err()
            .map(|reason| ValidationResult::Block {
                reason: reason.to_string(),
            });
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
        && super::tokenize::is_interpreter_information_query(command, arguments)
}

/// The first option of a read-only Git subcommand that makes it something
/// else: one that writes a file, or names or enables a program to run.
///
/// * `--output[=]<file>` (the diff family) writes the output to a file.
/// * `-O[<pager>]` / `--open-files-in-pager` (`grep`) opens matches in a
///   program. `diff -O<orderfile>` only reads, so the short form is `grep`'s.
/// * `-u` / `--upload-pack` / `--exec` (`ls-remote`) name the program run for
///   the repository.
/// * `--ext-diff`, `--textconv` and `--filters` turn on programs the
///   repository's configuration names where they are otherwise off.
///
/// Git accepts any unambiguous prefix of a long option, so prefixes count.
/// Everything after the subcommand is scanned: an operand that looks like one
/// of these is refused too, which costs a rare false refusal and no bypass.
fn git_option_that_writes_or_executes(parts: &[String]) -> Option<&str> {
    const LONG: &[&str] = &[
        "output",
        "open-files-in-pager",
        "upload-pack",
        "exec",
        "ext-diff",
        "textconv",
        "filters",
    ];
    let subcommand_at = parts
        .iter()
        .position(|part| Some(part.as_str()) == git_subcommand(parts))?;
    let subcommand = parts[subcommand_at].as_str();
    parts[subcommand_at + 1..]
        .iter()
        .map(String::as_str)
        .take_while(|argument| *argument != "--")
        .find(|argument| {
            if let Some(name) = argument.strip_prefix("--") {
                let mut name = name.split_once('=').map_or(name, |(name, _)| name);
                // Git's option parser accepts paired negations as enabling
                // options again. A single `--no-` disables the helper.
                while let Some(enabled) = name.strip_prefix("no-no-") {
                    name = enabled;
                }
                // These complete options only override the dangerous prefix
                // in subcommands that actually define them. In cat-file they
                // are abbreviations for textconv / filters instead.
                let is_plain_text =
                    name == "text" && matches!(subcommand, "diff" | "log" | "show" | "grep");
                let is_object_filter = name == "filter" && subcommand == "rev-list";
                if is_plain_text || is_object_filter {
                    return false;
                }
                // Even one letter can be unambiguous for a particular
                // subcommand (cat-file --t enables textconv).
                return !name.is_empty() && LONG.iter().any(|option| option.starts_with(name));
            }
            // Short options bundle, so `-nO<pager>` carries `-O` too.
            let bundles = |flag| argument.starts_with('-') && argument.contains(flag);
            match subcommand {
                "grep" => bundles('O'),
                "ls-remote" => bundles('u'),
                _ => false,
            }
        })
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
