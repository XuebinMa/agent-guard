//! Transparent command-wrapper unwrapping.
//!
//! Wrappers like `sudo`/`env`/`nice`/`nohup`/`timeout`/`doas` and bare
//! `NAME=value` assignment prefixes run another command given after the
//! wrapper's own options/operands. The validators must skip those tokens so
//! the *wrapped* command word re-enters every gate; otherwise a wrapper flag
//! (or its value) is mistaken for the command and the destructive sub-command
//! becomes invisible (audit 2026-05-18 / 2026-06-08).

/// A transparent command wrapper: a program that runs another command given
/// after the wrapper's own options/operands (e.g. `sudo -u root rm`,
/// `env FOO=1 rm`, `nice -n 10 rm`, `timeout 5 rm`). The validator must skip
/// the wrapper's tokens so the *wrapped* command word re-enters every gate;
/// otherwise a wrapper flag (or its value) is mistaken for the command and the
/// destructive sub-command becomes invisible (audit 2026-05-18 / 2026-06-08).
///
/// Only wrappers with a regular `<wrapper> [options] [operand]... COMMAND`
/// grammar are modeled here. Irregular spawners (`xargs`, `find -exec`,
/// `strace`, `nsenter`, `flock`, `unshare`, `watch`) need dedicated parsing
/// and are tracked in the audit follow-up issue rather than half-handled.
struct CommandWrapper {
    name: &'static str,
    /// Short option chars that consume the FOLLOWING token as their value
    /// (e.g. sudo `-u root`, nice `-n 10`, timeout `-s TERM`).
    arg_short_flags: &'static [char],
    /// Long options that consume the FOLLOWING token when no `=VALUE` is
    /// attached (e.g. env `--chdir /tmp`). Unknown long options are treated
    /// as boolean rather than guessing over the command word.
    arg_long_flags: &'static [&'static str],
    /// Count of non-flag positional operands the wrapper takes before the
    /// command word (e.g. `timeout DURATION cmd` has one).
    leading_operands: usize,
}

const COMMAND_WRAPPERS: &[CommandWrapper] = &[
    CommandWrapper {
        name: "sudo",
        arg_short_flags: &['C', 'D', 'g', 'h', 'p', 'R', 'r', 't', 'T', 'U', 'u'],
        arg_long_flags: &[
            "chdir",
            "close-from",
            "group",
            "host",
            "prompt",
            "chroot",
            "role",
            "type",
            "other-user",
            "user",
        ],
        leading_operands: 0,
    },
    CommandWrapper {
        name: "doas",
        arg_short_flags: &['u', 'C'],
        arg_long_flags: &[],
        leading_operands: 0,
    },
    CommandWrapper {
        name: "env",
        arg_short_flags: &['u', 'C'],
        arg_long_flags: &["unset", "chdir", "split-string", "argv0"],
        leading_operands: 0,
    },
    CommandWrapper {
        // Shell builtins that execute the command named by the next word.
        name: "command",
        arg_short_flags: &[],
        arg_long_flags: &[],
        leading_operands: 0,
    },
    CommandWrapper {
        name: "exec",
        arg_short_flags: &['a'],
        arg_long_flags: &[],
        leading_operands: 0,
    },
    CommandWrapper {
        name: "builtin",
        arg_short_flags: &[],
        arg_long_flags: &[],
        leading_operands: 0,
    },
    CommandWrapper {
        name: "nice",
        arg_short_flags: &['n'],
        arg_long_flags: &["adjustment"],
        leading_operands: 0,
    },
    CommandWrapper {
        name: "nohup",
        arg_short_flags: &[],
        arg_long_flags: &[],
        leading_operands: 0,
    },
    CommandWrapper {
        name: "timeout",
        arg_short_flags: &['s', 'k'],
        arg_long_flags: &["signal", "kill-after"],
        leading_operands: 1,
    },
    // ── irregular spawners with a regular-enough grammar (issue #55) ──────────
    // These run an arbitrary sub-command after their own flags. `find -exec`
    // and `xargs` are handled separately (their command word is mid-arguments
    // or their target comes from stdin); the rest fit the flag-skip model.
    CommandWrapper {
        // strace -o file -e expr -p pid CMD
        name: "strace",
        arg_short_flags: &['o', 'e', 'p', 'E', 's', 'a'],
        arg_long_flags: &["output", "trace", "attach", "string-limit"],
        leading_operands: 0,
    },
    CommandWrapper {
        name: "ltrace",
        arg_short_flags: &['o', 'e', 'p', 's', 'a', 'u'],
        arg_long_flags: &["output", "expr", "attach", "string-limit"],
        leading_operands: 0,
    },
    CommandWrapper {
        // nsenter -t pid -S uid -G gid CMD (option-arg flags only; the rare
        // `-r[dir]`/`-w[dir]` optional-arg forms are treated as boolean).
        name: "nsenter",
        arg_short_flags: &['t', 'S', 'G'],
        arg_long_flags: &["target", "setuid", "setgid"],
        leading_operands: 0,
    },
    CommandWrapper {
        // unshare's short flags are all boolean (-m/-u/-i/-n/-p/-U/-C/-T/-r/-f).
        name: "unshare",
        arg_short_flags: &[],
        arg_long_flags: &["map-user", "map-group", "propagation", "root", "wd"],
        leading_operands: 0,
    },
    CommandWrapper {
        // watch -n SECS CMD
        name: "watch",
        arg_short_flags: &['n'],
        arg_long_flags: &["interval"],
        leading_operands: 0,
    },
    CommandWrapper {
        // flock [-w secs] [-E code] <lockfile|fd> CMD — the lock target is a
        // leading operand before the command word.
        name: "flock",
        arg_short_flags: &['w', 'E'],
        arg_long_flags: &["timeout", "conflict-exit-code"],
        leading_operands: 1,
    },
    CommandWrapper {
        // xargs [-I repl] [-n N] [-P N] [-d delim] CMD — the command word
        // follows the flags; its *operands* come from stdin (see
        // `leads_with_target_hiding_spawner`).
        name: "xargs",
        // GNU -i/-e/-l take OPTIONAL attached values. They must not consume
        // the following command token when used bare.
        arg_short_flags: &['I', 'E', 'd', 'n', 'P', 's', 'a', 'L'],
        arg_long_flags: &[
            "delimiter",
            "max-args",
            "max-procs",
            "max-chars",
            "arg-file",
        ],
        leading_operands: 0,
    },
];

/// Normalize a command token to the executable name used by policy tables.
/// Shells accept path-qualified command words (`/bin/rm`, `./tool`); comparing
/// the literal token against `rm` would make those paths invisible.
pub(crate) fn command_name(token: &str) -> &str {
    token.rsplit(['/', '\\']).next().unwrap_or(token)
}

/// `NAME=value` shell variable-assignment prefix (e.g. `FOO=bar cmd`, or the
/// assignments `env` passes through). Mirrors the bash assignment grammar:
/// the run of bytes before the first `=` must be `[A-Za-z0-9_]` only.
fn is_env_assignment(token: &str) -> bool {
    token.contains('=')
        && token
            .as_bytes()
            .iter()
            .take_while(|&&b| b != b'=')
            .all(|&b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Skip one wrapper's own options and leading operands, returning the number
/// of tokens (within `args`, the slice *after* the wrapper name) to drop.
/// `--` terminates option parsing.
///
/// Short-option handling: an argument-taking flag must be the last char of a
/// bundle. If it is the last char (`-u`, `-knu`) its value is the next token,
/// so that token is consumed too; otherwise the value is attached (`-uroot`)
/// or the token is a boolean bundle (`-kn`) — either way it is self-contained.
fn skip_wrapper_tokens<S: AsRef<str>>(args: &[S], wrapper: &CommandWrapper) -> usize {
    let mut idx = 0;
    while idx < args.len() {
        let token = args[idx].as_ref();
        if token == "--" {
            idx += 1;
            break;
        }
        // A lone `-` or a non-option token ends the option run.
        if !token.starts_with('-') || token == "-" {
            break;
        }
        if let Some(option) = token.strip_prefix("--") {
            let (name, has_attached_value) = match option.split_once('=') {
                Some((name, _)) => (name, true),
                None => (option, false),
            };
            if !has_attached_value && wrapper.arg_long_flags.contains(&name) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        let flag_chars: Vec<char> = token.chars().skip(1).collect();
        match flag_chars
            .iter()
            .position(|c| wrapper.arg_short_flags.contains(c))
        {
            Some(pos) if pos + 1 == flag_chars.len() => idx += 2,
            _ => idx += 1,
        }
    }
    // Leading positional operands (e.g. timeout's DURATION).
    for _ in 0..wrapper.leading_operands {
        if idx < args.len() {
            idx += 1;
        }
    }
    idx
}

/// Strip leading `NAME=value` assignments and transparent command-wrapper
/// layers (`sudo`/`env`/`nice`/`nohup`/`timeout`/`doas`) so the returned slice
/// starts at the real command word. Handles nesting (`sudo env rm`) and
/// pre-/post-wrapper assignments (`FOO=1 sudo rm`, `env BAR=2 rm`).
pub(crate) fn unwrap_command_wrappers<S: AsRef<str>>(tokens: &[S]) -> &[S] {
    let mut slice = tokens;
    loop {
        // Skip leading assignments and shell negation prefixes. `!` changes
        // only the exit status; the following command still executes and must
        // pass the same policy gates.
        loop {
            let mut start = 0;
            while start < slice.len() && is_env_assignment(slice[start].as_ref()) {
                start += 1;
            }
            slice = &slice[start..];
            if slice.first().is_some_and(|token| token.as_ref() == "!") {
                slice = &slice[1..];
                continue;
            }
            break;
        }

        let Some(first) = slice.first().map(AsRef::as_ref) else {
            return slice;
        };
        let first = command_name(first);
        // `find ... -exec CMD ... ;` / `-execdir CMD ... +`: the sub-command is
        // mid-arguments, after the path and predicates, so the regular flag-skip
        // model cannot reach it. Extract the tokens between `-exec(dir)` and the
        // `;`/`+` terminator and continue unwrapping (handles `find -exec sudo
        // rm`). A `find` with no `-exec` is a plain read traversal.
        if first == "find" {
            if let Some(pos) = slice.iter().position(|t| {
                let s = t.as_ref();
                s == "-exec" || s == "-execdir"
            }) {
                let sub = &slice[pos + 1..];
                let end = sub
                    .iter()
                    .position(|t| {
                        let s = t.as_ref();
                        s == ";" || s == "+"
                    })
                    .unwrap_or(sub.len());
                slice = &sub[..end];
                continue;
            }
            return slice;
        }

        let Some(wrapper) = COMMAND_WRAPPERS.iter().find(|w| w.name == first) else {
            return slice; // real command word reached
        };

        let skipped = 1 + skip_wrapper_tokens(&slice[1..], wrapper);
        // Defensive: every wrapper consumes at least its own name, so `slice`
        // strictly shrinks and the loop always terminates.
        slice = &slice[skipped.min(slice.len())..];
    }
}

/// Whether the segment is launched through a spawner that supplies the
/// wrapped command's *operands* from somewhere the validator cannot see —
/// `find ... -exec` (paths from the filesystem traversal, e.g. `{}`) or
/// `xargs` (operands from stdin). When such a spawner wraps a write/state
/// command the write target is unverifiable, so the path gate must fail
/// closed rather than trust the (placeholder or absent) visible operands.
pub(crate) fn leads_with_target_hiding_spawner<S: AsRef<str>>(tokens: &[S]) -> bool {
    let mut slice = tokens;
    loop {
        while slice
            .first()
            .is_some_and(|token| is_env_assignment(token.as_ref()) || token.as_ref() == "!")
        {
            slice = &slice[1..];
        }
        let Some(first) = slice.first().map(|token| command_name(token.as_ref())) else {
            return false;
        };
        if first == "xargs" {
            return true;
        }
        if first == "find" {
            return slice.iter().any(|token| {
                let token = token.as_ref();
                token == "-exec" || token == "-execdir"
            });
        }
        let Some(wrapper) = COMMAND_WRAPPERS
            .iter()
            .find(|wrapper| wrapper.name == first)
        else {
            return false;
        };
        let skipped = 1 + skip_wrapper_tokens(&slice[1..], wrapper);
        slice = &slice[skipped.min(slice.len())..];
    }
}

/// Return whether a wrapped `find` invocation contains more than one
/// `-exec`/`-execdir` action. The current command extractor intentionally
/// handles one action; multiple actions are rejected in restricted modes so a
/// benign first action cannot hide a mutating later action.
pub(crate) fn has_multiple_find_exec_actions<S: AsRef<str>>(tokens: &[S]) -> bool {
    let mut slice = tokens;
    loop {
        while slice
            .first()
            .is_some_and(|token| is_env_assignment(token.as_ref()) || token.as_ref() == "!")
        {
            slice = &slice[1..];
        }
        let Some(first) = slice.first().map(|token| command_name(token.as_ref())) else {
            return false;
        };
        if first == "find" {
            return slice
                .iter()
                .filter(|token| matches!(token.as_ref(), "-exec" | "-execdir"))
                .count()
                > 1;
        }
        let Some(wrapper) = COMMAND_WRAPPERS
            .iter()
            .find(|wrapper| wrapper.name == first)
        else {
            return false;
        };
        let skipped = 1 + skip_wrapper_tokens(&slice[1..], wrapper);
        slice = &slice[skipped.min(slice.len())..];
    }
}

/// Detect GNU `env -S` / `--split-string`, whose option value is itself split
/// into the argv (including the command word) that `env` executes. Treating it
/// as an ordinary option value would discard executable syntax from policy
/// analysis, so restricted modes reject this unsupported wrapper grammar.
pub(crate) fn has_env_split_string<S: AsRef<str>>(tokens: &[S]) -> bool {
    let mut slice = tokens;
    loop {
        while slice
            .first()
            .is_some_and(|token| is_env_assignment(token.as_ref()) || token.as_ref() == "!")
        {
            slice = &slice[1..];
        }
        let Some(first) = slice.first().map(|token| command_name(token.as_ref())) else {
            return false;
        };
        if first == "env" {
            for token in &slice[1..] {
                let token = token.as_ref();
                if token == "--" || (!token.starts_with('-') && !is_env_assignment(token)) {
                    break;
                }
                let short_split = token.starts_with('-')
                    && !token.starts_with("--")
                    && token.chars().skip(1).any(|flag| flag == 'S');
                if short_split || token == "--split-string" || token.starts_with("--split-string=")
                {
                    return true;
                }
            }
        }
        let Some(wrapper) = COMMAND_WRAPPERS
            .iter()
            .find(|wrapper| wrapper.name == first)
        else {
            return false;
        };
        let skipped = 1 + skip_wrapper_tokens(&slice[1..], wrapper);
        slice = &slice[skipped.min(slice.len())..];
    }
}

/// Extract the command string that `watch` will re-parse through a shell.
/// `shell_split` preserves a quoted payload as one token, so joining the
/// post-watch tokens reconstructs a form that can re-enter the validator.
pub(crate) fn reparsed_watch_command<S: AsRef<str>>(tokens: &[S]) -> Option<String> {
    let mut slice = tokens;
    loop {
        while slice
            .first()
            .is_some_and(|token| is_env_assignment(token.as_ref()) || token.as_ref() == "!")
        {
            slice = &slice[1..];
        }
        let first = slice.first().map(|token| command_name(token.as_ref()))?;
        let wrapper = COMMAND_WRAPPERS
            .iter()
            .find(|wrapper| wrapper.name == first)?;
        let skipped = 1 + skip_wrapper_tokens(&slice[1..], wrapper);
        let inner = &slice[skipped.min(slice.len())..];
        if first == "watch" {
            if inner.is_empty() {
                return None;
            }
            return Some(
                inner
                    .iter()
                    .map(AsRef::as_ref)
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }
        slice = inner;
    }
}
