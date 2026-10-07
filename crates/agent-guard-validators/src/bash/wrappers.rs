//! Transparent command-wrapper unwrapping.
//!
//! Command launchers are deliberately split into three classes:
//! modeled transparent wrappers, known-but-opaque spawners, and ordinary
//! commands. Modeled wrappers are unwrapped so their child re-enters every
//! gate. Listed opaque spawners are rejected in restricted modes because
//! guessing their argument grammar would silently turn a parse error into an
//! allow. Unknown commands remain ordinary; argv inspection alone cannot prove
//! whether an arbitrary program will execute one of its arguments.

/// A transparent command wrapper: a program that runs another command given
/// after the wrapper's own options/operands (e.g. `sudo -u root rm`,
/// `env FOO=1 rm`, `nice -n 10 rm`, `timeout 5 rm`). The validator must skip
/// the wrapper's tokens so the *wrapped* command word re-enters every gate;
/// otherwise a wrapper flag (or its value) is mistaken for the command and the
/// destructive sub-command becomes invisible (audit 2026-05-18 / 2026-06-08).
///
/// Only wrappers with a regular `<wrapper> [options] [operand]... COMMAND`
/// grammar are modeled here. Known launchers whose grammar is not modeled may
/// be listed in `OPAQUE_COMMAND_LAUNCHERS` so restricted modes reject them.
///
/// Every option a wrapper is unwrapped through is named in one of the four
/// lists. An option in none of them makes the invocation opaque: whether it
/// takes a value decides which word is the command, and guessing "no" let an
/// abbreviated or unlisted value-taking option hand its value to the gates as
/// the command while the real command went unchecked.
struct CommandWrapper {
    name: &'static str,
    /// Short option chars that consume the FOLLOWING token as their value
    /// (e.g. sudo `-u root`, nice `-n 10`, timeout `-s TERM`).
    arg_short_flags: &'static [char],
    /// Long options that consume the FOLLOWING token when no `=VALUE` is
    /// attached (e.g. env `--chdir /tmp`).
    arg_long_flags: &'static [&'static str],
    /// Short option chars that take no value.
    bool_short_flags: &'static [char],
    /// Long options that take no value, or only an attached `=VALUE`.
    bool_long_flags: &'static [&'static str],
    /// Count of non-flag positional operands the wrapper takes before the
    /// command word (e.g. `timeout DURATION cmd` has one).
    leading_operands: usize,
}

const HELP_VERSION: &[&str] = &["help", "version"];

const COMMAND_WRAPPERS: &[CommandWrapper] = &[
    CommandWrapper {
        name: "sudo",
        arg_short_flags: &['C', 'D', 'g', 'h', 'p', 'R', 'r', 't', 'T', 'U', 'u'],
        arg_long_flags: &[
            "chdir",
            "close-from",
            "command-timeout",
            "group",
            "host",
            "prompt",
            "chroot",
            "role",
            "type",
            "other-user",
            "user",
        ],
        bool_short_flags: &[
            'A', 'b', 'B', 'E', 'e', 'H', 'i', 'K', 'k', 'l', 'N', 'n', 'P', 'S', 's', 'V', 'v',
        ],
        bool_long_flags: &[
            "askpass",
            "background",
            "bell",
            "preserve-env",
            "edit",
            "set-home",
            "help",
            "login",
            "remove-timestamp",
            "reset-timestamp",
            "list",
            "non-interactive",
            "preserve-groups",
            "stdin",
            "shell",
            "version",
            "validate",
            "no-update",
        ],
        leading_operands: 0,
    },
    CommandWrapper {
        // POSIX/GNU/BSD `time` executes the remaining argv. -o/-f and their
        // long spellings consume values.
        name: "time",
        arg_short_flags: &['o', 'f'],
        arg_long_flags: &["output", "format"],
        bool_short_flags: &['p', 'a', 'v', 'l', 'h', 'q', 'V'],
        bool_long_flags: &[
            "portability",
            "append",
            "verbose",
            "quiet",
            "help",
            "version",
        ],
        leading_operands: 0,
    },
    CommandWrapper {
        // proxychains[4] [-q] [-f CONFIG] COMMAND ...
        name: "proxychains",
        arg_short_flags: &['f'],
        arg_long_flags: &[],
        bool_short_flags: &['q'],
        bool_long_flags: &[],
        leading_operands: 0,
    },
    CommandWrapper {
        name: "proxychains4",
        arg_short_flags: &['f'],
        arg_long_flags: &[],
        bool_short_flags: &['q'],
        bool_long_flags: &[],
        leading_operands: 0,
    },
    CommandWrapper {
        // eatmydata [COMMAND [ARG...]]
        name: "eatmydata",
        arg_short_flags: &[],
        arg_long_flags: &[],
        bool_short_flags: &[],
        bool_long_flags: &[],
        leading_operands: 0,
    },
    CommandWrapper {
        name: "doas",
        arg_short_flags: &['u', 'C', 'a'],
        arg_long_flags: &[],
        bool_short_flags: &['L', 'n', 's'],
        bool_long_flags: &[],
        leading_operands: 0,
    },
    CommandWrapper {
        // GNU `-a ARG`, BSD `-P altpath`, FreeBSD `-L`/`-U user` take values.
        // `-S` is refused separately (`has_env_split_string`).
        name: "env",
        arg_short_flags: &['u', 'C', 'S', 'a', 'P', 'L', 'U'],
        arg_long_flags: &["unset", "chdir", "split-string", "argv0"],
        bool_short_flags: &['i', '0', 'v'],
        bool_long_flags: &[
            "ignore-environment",
            "null",
            "debug",
            "list-signal-handling",
            "default-signal",
            "ignore-signal",
            "block-signal",
            "help",
            "version",
        ],
        leading_operands: 0,
    },
    CommandWrapper {
        // Shell builtins that execute the command named by the next word.
        name: "command",
        arg_short_flags: &[],
        arg_long_flags: &[],
        bool_short_flags: &['p', 'v', 'V'],
        bool_long_flags: &[],
        leading_operands: 0,
    },
    CommandWrapper {
        name: "exec",
        arg_short_flags: &['a'],
        arg_long_flags: &[],
        bool_short_flags: &['c', 'l'],
        bool_long_flags: &[],
        leading_operands: 0,
    },
    CommandWrapper {
        name: "builtin",
        arg_short_flags: &[],
        arg_long_flags: &[],
        bool_short_flags: &[],
        bool_long_flags: &[],
        leading_operands: 0,
    },
    CommandWrapper {
        // `coproc COMMAND` runs COMMAND. The grammar only yields this simple
        // form as an ordinary command; `coproc NAME { … }` is rejected by it.
        name: "coproc",
        arg_short_flags: &[],
        arg_long_flags: &[],
        bool_short_flags: &[],
        bool_long_flags: &[],
        leading_operands: 0,
    },
    CommandWrapper {
        // `nice -10 cmd` is the historical spelling of `-n 10`.
        name: "nice",
        arg_short_flags: &['n'],
        arg_long_flags: &["adjustment"],
        bool_short_flags: &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'],
        bool_long_flags: HELP_VERSION,
        leading_operands: 0,
    },
    CommandWrapper {
        name: "nohup",
        arg_short_flags: &[],
        arg_long_flags: &[],
        bool_short_flags: &[],
        bool_long_flags: HELP_VERSION,
        leading_operands: 0,
    },
    CommandWrapper {
        name: "timeout",
        arg_short_flags: &['s', 'k'],
        arg_long_flags: &["signal", "kill-after"],
        bool_short_flags: &['v', 'f', 'p'],
        bool_long_flags: &[
            "foreground",
            "preserve-status",
            "verbose",
            "help",
            "version",
        ],
        leading_operands: 1,
    },
    CommandWrapper {
        // GNU coreutils: stdbuf -o0 CMD / stdbuf --output=0 CMD.
        name: "stdbuf",
        arg_short_flags: &['i', 'o', 'e'],
        arg_long_flags: &["input", "output", "error"],
        bool_short_flags: &[],
        bool_long_flags: HELP_VERSION,
        leading_operands: 0,
    },
    CommandWrapper {
        // util-linux setsid: all supported options are boolean; the first
        // non-option token is the command to execute.
        name: "setsid",
        arg_short_flags: &[],
        arg_long_flags: &[],
        bool_short_flags: &['c', 'f', 'w', 'h', 'V'],
        bool_long_flags: &["ctty", "fork", "wait", "help", "version"],
        leading_operands: 0,
    },
    // ── irregular spawners with a regular-enough grammar (issue #55) ──────────
    // These run an arbitrary sub-command after their own flags. `find -exec`
    // and `xargs` are handled separately (their command word is mid-arguments
    // or their target comes from stdin); the rest fit the flag-skip model.
    CommandWrapper {
        // strace -o file -e expr -p pid CMD
        name: "strace",
        arg_short_flags: &[
            'o', 'e', 'p', 'E', 's', 'a', 'u', 'b', 'I', 'O', 'S', 'P', 'X', 'U',
        ],
        arg_long_flags: &["output", "trace", "attach", "string-limit"],
        bool_short_flags: &[
            'c', 'C', 'd', 'D', 'f', 'F', 'h', 'i', 'k', 'n', 'N', 'q', 'r', 't', 'T', 'v', 'V',
            'w', 'x', 'y', 'Y', 'z', 'Z', 'A',
        ],
        bool_long_flags: HELP_VERSION,
        leading_operands: 0,
    },
    CommandWrapper {
        name: "ltrace",
        arg_short_flags: &[
            'o', 'e', 'p', 's', 'a', 'u', 'l', 'n', 'x', 'A', 'D', 'F', 'w',
        ],
        arg_long_flags: &["output", "expr", "attach", "string-limit"],
        bool_short_flags: &['b', 'c', 'C', 'f', 'h', 'i', 'L', 'r', 'S', 't', 'T', 'V'],
        bool_long_flags: HELP_VERSION,
        leading_operands: 0,
    },
    CommandWrapper {
        // nsenter -t pid -S uid -G gid CMD. The namespace switches take only
        // an attached file (`-m=file`, `--mount=file`).
        name: "nsenter",
        arg_short_flags: &['t', 'S', 'G'],
        arg_long_flags: &["target", "setuid", "setgid"],
        bool_short_flags: &[
            'a', 'm', 'u', 'i', 'n', 'p', 'U', 'C', 'T', 'r', 'w', 'F', 'Z', 'e', 'h', 'V',
        ],
        bool_long_flags: &[
            "all",
            "mount",
            "uts",
            "ipc",
            "net",
            "pid",
            "user",
            "cgroup",
            "time",
            "preserve-credentials",
            "root",
            "wd",
            "no-fork",
            "follow-context",
            "env",
            "help",
            "version",
        ],
        leading_operands: 0,
    },
    CommandWrapper {
        // unshare -S uid -G gid -R dir -w dir CMD.
        name: "unshare",
        arg_short_flags: &['S', 'G', 'R', 'w'],
        arg_long_flags: &[
            "map-user",
            "map-group",
            "map-users",
            "map-groups",
            "propagation",
            "root",
            "wd",
            "setuid",
            "setgid",
            "setgroups",
            "monotonic",
            "boottime",
        ],
        bool_short_flags: &[
            'm', 'u', 'i', 'n', 'p', 'U', 'C', 'T', 'r', 'f', 'c', 'h', 'V',
        ],
        bool_long_flags: &[
            "mount",
            "uts",
            "ipc",
            "net",
            "pid",
            "user",
            "cgroup",
            "time",
            "fork",
            "map-root-user",
            "map-current-user",
            "map-auto",
            "mount-proc",
            "kill-child",
            "keep-caps",
            "help",
            "version",
        ],
        leading_operands: 0,
    },
    CommandWrapper {
        // watch -n SECS CMD
        name: "watch",
        arg_short_flags: &['n', 'q'],
        arg_long_flags: &["interval", "equexit"],
        bool_short_flags: &['d', 'b', 'e', 'g', 'c', 'C', 't', 'x', 'p', 'w', 'h', 'v'],
        bool_long_flags: &[
            "differences",
            "beep",
            "errexit",
            "chgexit",
            "color",
            "no-color",
            "no-title",
            "exec",
            "precise",
            "no-wrap",
            "help",
            "version",
        ],
        leading_operands: 0,
    },
    CommandWrapper {
        // flock [-w secs] [-E code] <lockfile|fd> CMD — the lock target is a
        // leading operand before the command word. `flock FILE -c STRING`
        // gives STRING to a shell and is not unwrapped (see
        // `skip_wrapper_tokens`).
        name: "flock",
        arg_short_flags: &['w', 'E'],
        arg_long_flags: &["timeout", "wait", "conflict-exit-code"],
        bool_short_flags: &['s', 'x', 'e', 'u', 'n', 'o', 'v', 'F', 'h', 'V'],
        bool_long_flags: &[
            "shared",
            "exclusive",
            "unlock",
            "nonblock",
            "nb",
            "close",
            "verbose",
            "no-fork",
            "help",
            "version",
        ],
        leading_operands: 1,
    },
    CommandWrapper {
        // xargs [-I repl] [-n N] [-P N] [-d delim] CMD — the command word
        // follows the flags; its *operands* come from stdin (see
        // `leads_with_target_hiding_spawner`).
        name: "xargs",
        // GNU -i/-e/-l take OPTIONAL attached values. Bare, they are flags;
        // with a value attached the token is not understood and fails closed.
        arg_short_flags: &['I', 'J', 'E', 'd', 'n', 'P', 's', 'a', 'L', 'R', 'S'],
        arg_long_flags: &[
            "delimiter",
            "max-args",
            "max-procs",
            "max-chars",
            "arg-file",
            "process-slot-var",
        ],
        bool_short_flags: &['0', 't', 'p', 'r', 'x', 'o', 'i', 'e', 'l'],
        bool_long_flags: &[
            "null",
            "no-run-if-empty",
            "interactive",
            "verbose",
            "open-tty",
            "exit",
            "show-limits",
            "replace",
            "eof",
            "max-lines",
            "help",
            "version",
        ],
        leading_operands: 0,
    },
    CommandWrapper {
        // `busybox APPLET ARGS…`: the applet is the command.
        name: "busybox",
        arg_short_flags: &[],
        arg_long_flags: &[],
        bool_short_flags: &[],
        bool_long_flags: &[],
        leading_operands: 0,
    },
    CommandWrapper {
        name: "toybox",
        arg_short_flags: &[],
        arg_long_flags: &[],
        bool_short_flags: &[],
        bool_long_flags: &[],
        leading_operands: 0,
    },
    CommandWrapper {
        // macOS `caffeinate [-disu] [-t SECS] [-w PID] COMMAND`.
        name: "caffeinate",
        arg_short_flags: &['t', 'w'],
        arg_long_flags: &[],
        bool_short_flags: &['d', 'i', 'm', 's', 'u'],
        bool_long_flags: &[],
        leading_operands: 0,
    },
];

/// Programs known to spawn a child command whose option/operand grammar is not
/// modeled above. Restricted modes reject these listed launchers. Membership
/// is deliberately conservative, but it is not an exhaustive launcher class.
const OPAQUE_COMMAND_LAUNCHERS: &[&str] = &[
    "numactl",
    "prlimit",
    "runuser",
    "systemd-run",
    // `arch -arch NAME`, `script FILE CMD` / `script -c STRING`, `chroot DIR`
    // and `setpriv` all end in a command; none has its grammar modeled.
    "arch",
    "script",
    "chroot",
    "setpriv",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpecializedLauncherDisposition {
    /// The launcher will exec the argv suffix beginning at this index.
    ChildAt(usize),
    /// The invocation operates on an existing process and never execs a child.
    ExistingProcess(&'static str),
    /// The invocation only prints metadata/help or has no child command.
    NoChild,
    /// The launcher was recognised but its option grammar was not understood.
    Opaque(&'static str),
}

enum LauncherLayer<'a, S> {
    Child(&'a [S]),
    ExistingProcess(&'static str),
    NoChild,
    Opaque(&'static str),
    NotLauncher,
}

enum ResolutionKind {
    Command,
    ExistingProcess(&'static str),
    NoChild,
    Opaque(&'static str),
}

struct CommandLayerResolution<'a, S> {
    argv: &'a [S],
    removed_any: bool,
    kind: ResolutionKind,
}

/// Classification of the first executable layer in a resolved shell command.
pub(crate) enum LauncherDisposition {
    /// One or more modeled layers were removed.
    Transparent,
    /// A known child-process launcher has no trustworthy grammar model.
    Opaque(&'static str),
    /// A modeled launcher is operating on an existing process rather than
    /// executing a child command. Restricted modes keep this control surface
    /// closed until query and mutation forms are modeled separately.
    ExistingProcess(&'static str),
    /// The command is not a launcher known to this validator.
    Ordinary,
}

/// Normalize a command token to the executable name used by policy tables.
/// Shells accept path-qualified command words (`/bin/rm`, `./tool`); comparing
/// the literal token against `rm` would make those paths invisible.
pub(crate) fn command_name(token: &str) -> &str {
    token.rsplit(['/', '\\']).next().unwrap_or(token)
}

/// Assignment operands of the explicitly modeled env/sudo programs. Shell
/// assignment prefixes have already been removed by their AST node identity;
/// a command word with this spelling must not be dropped merely for having `=`.
fn is_env_assignment(token: &str) -> bool {
    token.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

/// Skip one wrapper's own options and leading operands, returning the number
/// of tokens (within `args`, the slice *after* the wrapper name) to drop.
/// `--` terminates option parsing.
///
/// Short-option handling: an argument-taking flag must be the last char of a
/// bundle. If it is the last char (`-u`, `-knu`) its value is the next token,
/// so that token is consumed too; otherwise the value is attached (`-uroot`)
/// or the token is a boolean bundle (`-kn`) — either way it is self-contained.
///
/// Returns `None` when an option is not one the wrapper's table names,
/// including an unknown long option with an attached `=VALUE`. An attached
/// value can still carry executable syntax (`env --split=...` abbreviates
/// `--split-string`), so knowing where the next token starts is not enough to
/// establish that the wrapper is transparent.
fn skip_wrapper_tokens<S: AsRef<str>>(args: &[S], wrapper: &CommandWrapper) -> Option<usize> {
    let mut idx = 0;
    while idx < args.len() {
        let token = args[idx].as_ref();
        if token == "--" {
            idx += 1;
            break;
        }
        // `env -` is `env -i`; anywhere else a lone `-` is an operand.
        if token == "-" && wrapper.name == "env" {
            idx += 1;
            continue;
        }
        // A lone `-` or a non-option token ends the option run.
        if !token.starts_with('-') || token == "-" {
            break;
        }
        if let Some(option) = token.strip_prefix("--") {
            let (name, attached) = option
                .split_once('=')
                .map_or((option, false), |(name, _)| (name, true));
            idx += if wrapper.arg_long_flags.contains(&name) {
                if attached {
                    1
                } else {
                    2
                }
            } else if wrapper.bool_long_flags.contains(&name) {
                1
            } else {
                return None;
            };
            continue;
        }
        let mut flags = token.chars().skip(1).peekable();
        idx += 1;
        while let Some(flag) = flags.next() {
            if wrapper.arg_short_flags.contains(&flag) {
                // Last in the bundle: the value is the next token. Otherwise
                // the rest of this token is the value.
                if flags.peek().is_none() {
                    idx += 1;
                }
                break;
            }
            if !wrapper.bool_short_flags.contains(&flag) {
                return None;
            }
        }
    }
    // Leading positional operands (e.g. timeout's DURATION).
    for _ in 0..wrapper.leading_operands {
        if idx < args.len() {
            idx += 1;
        }
    }
    // These programs, unlike nice/timeout/command, consume assignment
    // operands before the child argv. Quoting does not change env's grammar.
    if matches!(wrapper.name, "env" | "sudo") {
        while args
            .get(idx)
            .is_some_and(|token| is_env_assignment(token.as_ref()))
        {
            idx += 1;
        }
    }
    // `flock FILE -c STRING` runs STRING through a shell, so what follows the
    // lock file is not an argv to unwrap.
    if wrapper.name == "flock"
        && args
            .get(idx)
            .is_some_and(|next| matches!(next.as_ref(), "-c" | "--command"))
    {
        return None;
    }
    Some(idx)
}

fn parse_ionice_layer<S: AsRef<str>>(tokens: &[S]) -> SpecializedLauncherDisposition {
    let mut index = 1;
    while index < tokens.len() {
        let token = tokens[index].as_ref();
        if token == "--" {
            index += 1;
            break;
        }
        if token == "-" || !token.starts_with('-') {
            break;
        }

        if let Some(option) = token.strip_prefix("--") {
            let (name, attached) = option
                .split_once('=')
                .map_or((option, false), |(name, _)| (name, true));
            match name {
                "pid" | "pgid" | "uid" => {
                    return SpecializedLauncherDisposition::ExistingProcess("ionice")
                }
                "class" | "classdata" => {
                    if attached {
                        index += 1;
                    } else if index + 1 < tokens.len() {
                        index += 2;
                    } else {
                        return SpecializedLauncherDisposition::Opaque("ionice");
                    }
                }
                "ignore" => index += 1,
                "help" | "version" => return SpecializedLauncherDisposition::NoChild,
                _ => return SpecializedLauncherDisposition::Opaque("ionice"),
            }
            continue;
        }

        let flags: Vec<char> = token.chars().skip(1).collect();
        let mut position = 0;
        let mut consumed_token = false;
        while position < flags.len() {
            match flags[position] {
                'p' | 'P' | 'u' => {
                    return SpecializedLauncherDisposition::ExistingProcess("ionice")
                }
                'c' | 'n' => {
                    if position + 1 < flags.len() {
                        index += 1;
                    } else if index + 1 < tokens.len() {
                        index += 2;
                    } else {
                        return SpecializedLauncherDisposition::Opaque("ionice");
                    }
                    consumed_token = true;
                    break;
                }
                't' => position += 1,
                'h' | 'V' => return SpecializedLauncherDisposition::NoChild,
                _ => return SpecializedLauncherDisposition::Opaque("ionice"),
            }
        }
        if !consumed_token {
            index += 1;
        }
    }

    if index < tokens.len() {
        SpecializedLauncherDisposition::ChildAt(index)
    } else {
        SpecializedLauncherDisposition::NoChild
    }
}

fn parse_taskset_layer<S: AsRef<str>>(tokens: &[S]) -> SpecializedLauncherDisposition {
    let mut index = 1;
    while index < tokens.len() {
        let token = tokens[index].as_ref();
        if token == "--" {
            index += 1;
            break;
        }
        if token == "-" || !token.starts_with('-') {
            break;
        }

        if let Some(option) = token.strip_prefix("--") {
            let name = option.split_once('=').map_or(option, |(name, _)| name);
            match name {
                "pid" => return SpecializedLauncherDisposition::ExistingProcess("taskset"),
                "all-tasks" | "cpu-list" => index += 1,
                "help" | "version" => return SpecializedLauncherDisposition::NoChild,
                _ => return SpecializedLauncherDisposition::Opaque("taskset"),
            }
            continue;
        }

        for flag in token.chars().skip(1) {
            match flag {
                'p' => return SpecializedLauncherDisposition::ExistingProcess("taskset"),
                'a' | 'c' => {}
                'h' | 'V' => return SpecializedLauncherDisposition::NoChild,
                _ => return SpecializedLauncherDisposition::Opaque("taskset"),
            }
        }
        index += 1;
    }

    if index + 1 < tokens.len() {
        SpecializedLauncherDisposition::ChildAt(index + 1)
    } else {
        SpecializedLauncherDisposition::NoChild
    }
}

fn parse_chrt_layer<S: AsRef<str>>(tokens: &[S]) -> SpecializedLauncherDisposition {
    let mut index = 1;
    let mut policy_requires_priority = true; // util-linux defaults to SCHED_RR.
    let mut sticky_priority_requirement = false;

    while index < tokens.len() {
        let token = tokens[index].as_ref();
        if token == "--" {
            index += 1;
            break;
        }
        if token == "-" || !token.starts_with('-') {
            break;
        }

        if let Some(option) = token.strip_prefix("--") {
            let (name, attached) = option
                .split_once('=')
                .map_or((option, false), |(name, _)| (name, true));
            match name {
                "pid" => return SpecializedLauncherDisposition::ExistingProcess("chrt"),
                "help" | "version" | "max" => return SpecializedLauncherDisposition::NoChild,
                "fifo" | "rr" => {
                    policy_requires_priority = true;
                    sticky_priority_requirement = true;
                    index += 1;
                }
                "batch" | "deadline" | "ext" | "idle" | "other" => {
                    policy_requires_priority = false;
                    index += 1;
                }
                "all-tasks" | "deadline-overrun" | "reset-on-fork" | "reclaim-grub" | "verbose" => {
                    index += 1
                }
                "sched-runtime" | "sched-period" | "sched-deadline" | "clamp-min" | "clamp-max" => {
                    if attached {
                        index += 1;
                    } else if index + 1 < tokens.len() {
                        index += 2;
                    } else {
                        return SpecializedLauncherDisposition::Opaque("chrt");
                    }
                }
                _ => return SpecializedLauncherDisposition::Opaque("chrt"),
            }
            continue;
        }

        let flags: Vec<char> = token.chars().skip(1).collect();
        let mut position = 0;
        let mut consumed_token = false;
        while position < flags.len() {
            match flags[position] {
                'p' => return SpecializedLauncherDisposition::ExistingProcess("chrt"),
                'h' | 'V' | 'm' => return SpecializedLauncherDisposition::NoChild,
                'f' | 'r' => {
                    policy_requires_priority = true;
                    sticky_priority_requirement = true;
                    position += 1;
                }
                'b' | 'd' | 'e' | 'i' | 'o' => {
                    policy_requires_priority = false;
                    position += 1;
                }
                'a' | 'O' | 'R' | 'G' | 'v' => position += 1,
                'D' | 'P' | 'T' | 'U' | 'X' => {
                    if position + 1 < flags.len() {
                        index += 1;
                    } else if index + 1 < tokens.len() {
                        index += 2;
                    } else {
                        return SpecializedLauncherDisposition::Opaque("chrt");
                    }
                    consumed_token = true;
                    break;
                }
                _ => return SpecializedLauncherDisposition::Opaque("chrt"),
            }
        }
        if !consumed_token {
            index += 1;
        }
    }

    if index >= tokens.len() {
        return SpecializedLauncherDisposition::NoChild;
    }

    let requires_priority = sticky_priority_requirement || policy_requires_priority;
    let first_is_priority = tokens[index]
        .as_ref()
        .chars()
        .all(|character| character.is_ascii_digit());
    let mut command_index = if first_is_priority {
        index + 1
    } else if requires_priority {
        return SpecializedLauncherDisposition::Opaque("chrt");
    } else {
        index
    };
    if tokens
        .get(command_index)
        .is_some_and(|token| token.as_ref() == "--")
    {
        command_index += 1;
    }

    if command_index < tokens.len() {
        SpecializedLauncherDisposition::ChildAt(command_index)
    } else {
        SpecializedLauncherDisposition::NoChild
    }
}

fn specialized_launcher_layer<S: AsRef<str>>(
    tokens: &[S],
) -> Option<SpecializedLauncherDisposition> {
    match tokens.first().map(|token| command_name(token.as_ref())) {
        Some("ionice") => Some(parse_ionice_layer(tokens)),
        Some("taskset") => Some(parse_taskset_layer(tokens)),
        Some("chrt") => Some(parse_chrt_layer(tokens)),
        _ => None,
    }
}

fn launcher_layer<S: AsRef<str>>(tokens: &[S]) -> LauncherLayer<'_, S> {
    let Some(first) = tokens.first().map(|token| command_name(token.as_ref())) else {
        return LauncherLayer::NotLauncher;
    };

    if first == "find" {
        if let Some(position) = tokens
            .iter()
            .position(|token| matches!(token.as_ref(), "-exec" | "-execdir"))
        {
            let child = &tokens[position + 1..];
            let end = child
                .iter()
                .position(|token| matches!(token.as_ref(), ";" | "+"))
                .unwrap_or(child.len());
            return LauncherLayer::Child(&child[..end]);
        }
        return LauncherLayer::NotLauncher;
    }

    if let Some(disposition) = specialized_launcher_layer(tokens) {
        return match disposition {
            SpecializedLauncherDisposition::ChildAt(index) => {
                LauncherLayer::Child(&tokens[index.min(tokens.len())..])
            }
            SpecializedLauncherDisposition::ExistingProcess(name) => {
                LauncherLayer::ExistingProcess(name)
            }
            SpecializedLauncherDisposition::NoChild => LauncherLayer::NoChild,
            SpecializedLauncherDisposition::Opaque(name) => LauncherLayer::Opaque(name),
        };
    }

    if let Some(name) = OPAQUE_COMMAND_LAUNCHERS
        .iter()
        .copied()
        .find(|candidate| *candidate == first)
    {
        return LauncherLayer::Opaque(name);
    }

    let Some(wrapper) = COMMAND_WRAPPERS
        .iter()
        .find(|wrapper| wrapper.name == first)
    else {
        return LauncherLayer::NotLauncher;
    };
    match skip_wrapper_tokens(&tokens[1..], wrapper) {
        Some(skipped) => LauncherLayer::Child(&tokens[(1 + skipped).min(tokens.len())..]),
        None => LauncherLayer::Opaque(wrapper.name),
    }
}

fn resolve_command_layers<S: AsRef<str>>(tokens: &[S]) -> CommandLayerResolution<'_, S> {
    let mut slice = tokens;
    let mut removed_any = false;
    loop {
        match launcher_layer(slice) {
            LauncherLayer::Child(child) => {
                removed_any = true;
                slice = child;
            }
            LauncherLayer::ExistingProcess(name) => {
                return CommandLayerResolution {
                    argv: slice,
                    removed_any,
                    kind: ResolutionKind::ExistingProcess(name),
                }
            }
            LauncherLayer::NoChild => {
                return CommandLayerResolution {
                    argv: slice,
                    removed_any,
                    kind: ResolutionKind::NoChild,
                }
            }
            LauncherLayer::Opaque(name) => {
                return CommandLayerResolution {
                    argv: slice,
                    removed_any,
                    kind: ResolutionKind::Opaque(name),
                }
            }
            LauncherLayer::NotLauncher => {
                return CommandLayerResolution {
                    argv: slice,
                    removed_any,
                    kind: ResolutionKind::Command,
                }
            }
        }
    }
}

/// Strip modeled wrappers from AST-resolved argv. The AST already excludes
/// shell assignment and negation syntax; ordinary words must not be guessed
/// to be those prefixes. A listed opaque layer,
/// an existing-process mode, or a no-child invocation stops resolution.
pub(crate) fn unwrap_command_wrappers<S: AsRef<str>>(tokens: &[S]) -> &[S] {
    resolve_command_layers(tokens).argv
}

/// Classify a resolved argv without guessing at unknown launcher grammars.
/// Transparent layers are removed first, so nesting such as
/// `env systemd-run ...` is still recognized as opaque.
pub(crate) fn classify_command_launcher<S: AsRef<str>>(tokens: &[S]) -> LauncherDisposition {
    let resolution = resolve_command_layers(tokens);
    match resolution.kind {
        ResolutionKind::ExistingProcess(name) => LauncherDisposition::ExistingProcess(name),
        ResolutionKind::Opaque(name) => LauncherDisposition::Opaque(name),
        ResolutionKind::Command | ResolutionKind::NoChild if resolution.removed_any => {
            LauncherDisposition::Transparent
        }
        ResolutionKind::Command | ResolutionKind::NoChild => LauncherDisposition::Ordinary,
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
        match launcher_layer(slice) {
            LauncherLayer::Child(child) => slice = child,
            _ => return false,
        }
    }
}

/// Return whether a wrapped `find` invocation contains more than one
/// `-exec`/`-execdir` action. The current command extractor intentionally
/// handles one action; multiple actions are rejected in restricted modes so a
/// benign first action cannot hide a mutating later action.
pub(crate) fn has_multiple_find_exec_actions<S: AsRef<str>>(tokens: &[S]) -> bool {
    let mut slice = tokens;
    loop {
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
        match launcher_layer(slice) {
            LauncherLayer::Child(child) => slice = child,
            _ => return false,
        }
    }
}

/// Detect GNU `env -S` / `--split-string`, whose option value is itself split
/// into the argv (including the command word) that `env` executes. Treating it
/// as an ordinary option value would discard executable syntax from policy
/// analysis, so restricted modes reject this unsupported wrapper grammar.
pub(crate) fn has_env_split_string<S: AsRef<str>>(tokens: &[S]) -> bool {
    let mut slice = tokens;
    loop {
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
        match launcher_layer(slice) {
            LauncherLayer::Child(child) => slice = child,
            _ => return false,
        }
    }
}

/// Extract the command string that `watch` will re-parse through a shell.
/// `shell_split` preserves a quoted payload as one token, so joining the
/// post-watch tokens reconstructs a form that can re-enter the validator.
pub(crate) fn reparsed_watch_command<S: AsRef<str>>(tokens: &[S]) -> Option<String> {
    let mut slice = tokens;
    loop {
        let first = slice.first().map(|token| command_name(token.as_ref()))?;
        let LauncherLayer::Child(inner) = launcher_layer(slice) else {
            return None;
        };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listed_opaque_launchers_are_classified_fail_closed() {
        assert!(!OPAQUE_COMMAND_LAUNCHERS.is_empty());
        for launcher in OPAQUE_COMMAND_LAUNCHERS {
            let argv = [*launcher, "git", "push", "origin", "main"];
            assert!(
                matches!(
                    classify_command_launcher(&argv),
                    LauncherDisposition::Opaque(name) if name == *launcher
                ),
                "listed opaque launcher was not classified: {launcher}"
            );
        }
    }

    #[test]
    fn launcher_classification_keeps_transparent_and_ordinary_commands_distinct() {
        for launcher in ["time", "proxychains", "proxychains4", "eatmydata"] {
            let argv = [launcher, "git", "push", "origin", "main"];
            match classify_command_launcher(&argv) {
                LauncherDisposition::Transparent => {
                    assert_eq!(unwrap_command_wrappers(&argv).first().copied(), Some("git"));
                }
                _ => panic!("modeled launcher was not transparent: {launcher}"),
            }
        }

        let argv = ["echo", "git", "push"];
        assert!(matches!(
            classify_command_launcher(&argv),
            LauncherDisposition::Ordinary
        ));
    }

    #[test]
    fn util_linux_launchers_unwrap_only_command_mode() {
        let cases: &[(&[&str], &[&str])] = &[
            (&["ionice", "cargo", "build"], &["cargo", "build"]),
            (&["ionice", "-c3", "cargo", "build"], &["cargo", "build"]),
            (&["ionice", "-tc", "3", "cargo", "test"], &["cargo", "test"]),
            (
                &["ionice", "--class", "idle", "cargo", "test"],
                &["cargo", "test"],
            ),
            (
                &["taskset", "-c", "0", "cargo", "bench"],
                &["cargo", "bench"],
            ),
            (&["taskset", "0x1", "make"], &["make"]),
            (&["taskset", "--", "0x1", "make"], &["make"]),
            (
                &["taskset", "-c", "0", "cargo", "build", "-p"],
                &["cargo", "build", "-p"],
            ),
            (&["chrt", "-b", "0", "make"], &["make"]),
            (&["chrt", "-b", "make"], &["make"]),
            (&["chrt", "-f", "10", "make"], &["make"]),
            (
                &["chrt", "-b", "-T100p", "cargo", "build"],
                &["cargo", "build"],
            ),
            (&["chrt", "-b", "0", "--", "make"], &["make"]),
            (
                &["chrt", "--batch", "0", "cargo", "build"],
                &["cargo", "build"],
            ),
        ];

        for (argv, expected) in cases {
            assert_eq!(
                unwrap_command_wrappers(argv),
                *expected,
                "command mode was not unwrapped: {argv:?}"
            );
            assert!(matches!(
                classify_command_launcher(argv),
                LauncherDisposition::Transparent
            ));
        }
    }

    #[test]
    fn util_linux_pid_modes_do_not_treat_identifiers_as_commands() {
        for argv in [
            &["ionice", "-p", "1234"][..],
            &["ionice", "-p1234"][..],
            &["ionice", "--pid=1234"][..],
            &["ionice", "-P", "7", "8"][..],
            &["ionice", "-u0", "1000"][..],
            &["taskset", "-pc", "0", "1234"][..],
            &["taskset", "-p", "1234"][..],
            &["taskset", "--pid", "1234"][..],
            &["chrt", "-p", "1234"][..],
            &["chrt", "-p", "-b", "0", "1234"][..],
            &["chrt", "-pT100"][..],
            &["chrt", "--pid", "10", "1234"][..],
        ] {
            assert_eq!(
                unwrap_command_wrappers(argv),
                argv,
                "PID mode exposed an identifier as a child command: {argv:?}"
            );
            assert!(matches!(
                classify_command_launcher(argv),
                LauncherDisposition::ExistingProcess(_)
            ));
        }
    }

    #[test]
    fn ambiguous_util_linux_launcher_syntax_fails_closed() {
        for argv in [
            &["ionice", "--unknown", "git", "push"][..],
            &["taskset", "--unknown", "git", "push"][..],
            &["chrt", "--unknown", "git", "push"][..],
            &["env", "ionice", "--unknown", "git", "push"][..],
        ] {
            assert!(matches!(
                classify_command_launcher(argv),
                LauncherDisposition::Opaque(_)
            ));
        }
    }

    #[test]
    fn unknown_attached_long_wrapper_options_are_not_transparent() {
        for argv in [
            &["env", "--split=sh -c true", "cat"][..],
            &["env", "--future-option=value", "cat"][..],
            &["nice", "--adj=5", "cat"][..],
            &["timeout", "--sig=TERM", "5", "cat"][..],
        ] {
            assert!(
                matches!(
                    classify_command_launcher(argv),
                    LauncherDisposition::Opaque(_)
                ),
                "an unknown attached option was classified transparent: {argv:?}"
            );
            assert_eq!(unwrap_command_wrappers(argv), argv);
        }
    }

    #[test]
    fn modeled_attached_long_wrapper_options_keep_the_child_visible() {
        for (argv, child) in [
            (
                &["env", "--unset=HOME", "cat", "file"][..],
                &["cat", "file"][..],
            ),
            (&["timeout", "--signal=TERM", "5", "cat"][..], &["cat"][..]),
            (&["sudo", "--preserve-env=PATH", "cat"][..], &["cat"][..]),
        ] {
            assert!(matches!(
                classify_command_launcher(argv),
                LauncherDisposition::Transparent
            ));
            assert_eq!(unwrap_command_wrappers(argv), child);
        }
    }

    #[test]
    fn bsd_xargs_replacement_flag_does_not_hide_child_command() {
        let argv = ["xargs", "-J", "%", "rm"];
        assert_eq!(unwrap_command_wrappers(&argv), &["rm"]);
        assert!(leads_with_target_hiding_spawner(&argv));
    }
}
