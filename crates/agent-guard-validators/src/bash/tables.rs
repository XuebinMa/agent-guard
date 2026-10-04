//! Denylist constant tables shared across the bash validation submodules.

pub(crate) const WRITE_COMMANDS: &[&str] = &[
    "rm", "mv", "cp", "install", "touch", "mkdir", "rmdir", "chmod", "chown", "chgrp", "ln",
    "link", "unlink", "dd", "truncate", "mkfs", "mount", "umount", "tar", "zip", "unzip", "gzip",
    "gunzip", "bzip2", "bunzip2", "7z", "xz", "unxz", "tee", "apt", "apt-get", "yum", "dnf", "npm",
    "pip", "pip3", "cargo",
];

/// Executables whose ordinary operation is sufficiently narrow to classify as
/// read-only without inspecting an embedded language or an open-ended plugin
/// surface. This is intentionally an allowlist: an unknown executable is code,
/// not evidence that no write can occur.
pub(crate) const READ_ONLY_COMMANDS: &[&str] = &[
    ":", "[", "basename", "cat", "cmp", "comm", "cut", "diff", "dirname", "echo", "egrep", "env",
    "false", "fgrep", "file", "grep", "head", "id", "ls", "printf", "pwd", "readlink", "realpath",
    "rg", "stat", "tail", "test", "true", "uname", "wc", "which", "whoami",
];

pub(crate) const STATE_MODIFYING_COMMANDS: &[&str] = &[
    "kill",
    "pkill",
    "killall",
    "service",
    "systemctl",
    "shutdown",
    "reboot",
    "su",
];

pub(crate) const WRITE_REDIRECTIONS: &[&str] = &[">", ">>", ">&", ">|"];

/// Redirections that consume the next token as a filesystem path.
pub(crate) const READ_PATH_REDIRECTIONS: &[&str] = &["<"];

/// Read-side redirections whose target is data, not a path. Listed here
/// only so the tokenizer doesn't misclassify them; they do not yield
/// path-validation targets.
///
/// `<<`  — here-doc; the next token is a delimiter word, not a file.
/// `<<<` — here-string; the next token is the literal string content.
#[allow(dead_code)]
pub(crate) const READ_DATA_REDIRECTIONS: &[&str] = &["<<", "<<<"];

/// Environment-variable name prefixes whose assignment indicates code
/// injection. Matched against `shell_split` tokens with a `<NAME>=` prefix
/// so that quoting which splits the literal across raw bytes (e.g.
/// `env L'D'_PRELOAD=...`) is still caught — bash quote-stripping rejoins
/// the segments before we see them. Filenames that merely contain the
/// literal substring (e.g. `cat /workspace/log_LD_PRELOAD.txt`) are no
/// longer false-positives, since they never appear as `<NAME>=...`.
pub(crate) const DANGEROUS_ENV_VAR_PREFIXES: &[&str] = &[
    "LD_PRELOAD=",
    "DYLD_INSERT_LIBRARIES=",
    "PYTHONPATH=",
    "NODE_OPTIONS=",
];

/// Environment variable names whose value is a program that a later command in
/// the same line will execute, or that inject arbitrary Git configuration
/// (which can name such a program, e.g. `core.pager`). An agent in `ReadOnly`
/// mode can set one of these and then run an allow-listed read-only command
/// (`GIT_PAGER=cmd git -p log`, `GIT_SSH_COMMAND=cmd git ls-remote host:repo`)
/// to execute `cmd`, so the assignment itself is refused in that mode. These
/// are not refused in `WorkspaceWrite`, which already permits running arbitrary
/// programs directly.
///
/// Compared with a prefix, the Git config family must match a leading segment
/// (`GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_0`), so it is kept separate below.
pub(crate) const CODE_EXECUTION_ENV_VARS: &[&str] = &[
    "GIT_PAGER",
    "PAGER",
    "GIT_EXTERNAL_DIFF",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_PROXY_COMMAND",
    "GIT_EDITOR",
    "GIT_SEQUENCE_EDITOR",
    "EDITOR",
    "VISUAL",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
];

/// Leading segments of environment variable names that inject Git
/// configuration whose contents the command line does not show, and which can
/// therefore smuggle a `core.pager` / `core.sshCommand` program into an
/// otherwise read-only Git call.
pub(crate) const GIT_CONFIG_ENV_PREFIXES: &[&str] = &[
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY_",
    "GIT_CONFIG_VALUE_",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_PARAMETERS",
];

/// Whether an environment variable `name` can cause command execution in a
/// subsequent `ReadOnly` command.
pub(crate) fn is_code_execution_env_var(name: &str) -> bool {
    CODE_EXECUTION_ENV_VARS.contains(&name)
        || GIT_CONFIG_ENV_PREFIXES
            .iter()
            .any(|prefix| name == *prefix || name.starts_with(prefix))
}

/// Interpreters that accept an inline-code flag (`-c`, `-e`, `-r`). When
/// invoked with one of those flags, the interpreter's argument is an
/// opaque program that the validator cannot introspect — so it must be
/// blocked in ReadOnly mode to prevent destructive operations laundered
/// through `python3 -c`, `perl -e`, etc.
pub(crate) const INLINE_CODE_INTERPRETERS: &[&str] = &[
    "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php", "sh", "bash", "zsh",
    "ksh", "dash", "fish", "awk",
];

pub(crate) const INLINE_CODE_FLAGS: &[&str] = &["-c", "-e", "-r", "--command", "--exec"];

/// Builtins that re-parse string arguments as shell code, regardless of
/// quoting. They launder substitution past the context-aware substitution
/// gate (`'$(rm -rf /)'` is literal as a string but executable once `eval`
/// re-parses it). Blocked in ReadOnly + WorkspaceWrite modes, same posture
/// as `python -c` / `bash -c`.
///
/// `.` is the POSIX-portable spelling of `source`.
pub(crate) const CODE_LAUNDERING_COMMANDS: &[&str] = &["eval", "source", "."];

pub(crate) const DESTRUCTIVE_PATTERNS: &[(&str, &str)] = &[
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

pub(crate) const ALWAYS_DESTRUCTIVE_COMMANDS: &[&str] = &["shred", "wipefs"];
