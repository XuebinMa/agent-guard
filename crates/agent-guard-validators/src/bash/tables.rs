//! Denylist constant tables shared across the bash validation submodules.

pub(crate) const WRITE_COMMANDS: &[&str] = &[
    "rm", "mv", "cp", "touch", "mkdir", "rmdir", "chmod", "chown", "chgrp", "ln", "link", "unlink",
    "dd", "mkfs", "mount", "umount", "tar", "zip", "unzip", "gzip", "gunzip", "bzip2", "bunzip2",
    "7z", "xz", "unxz", "tee", "apt", "apt-get", "yum", "dnf", "npm", "pip", "pip3", "cargo",
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
