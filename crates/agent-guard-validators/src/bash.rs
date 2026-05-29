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

/// Environment-variable name prefixes whose assignment indicates code
/// injection. Matched against `shell_split` tokens with a `<NAME>=` prefix
/// so that quoting which splits the literal across raw bytes (e.g.
/// `env L'D'_PRELOAD=...`) is still caught — bash quote-stripping rejoins
/// the segments before we see them. Filenames that merely contain the
/// literal substring (e.g. `cat /workspace/log_LD_PRELOAD.txt`) are no
/// longer false-positives, since they never appear as `<NAME>=...`.
const DANGEROUS_ENV_VAR_PREFIXES: &[&str] = &[
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
const INLINE_CODE_INTERPRETERS: &[&str] = &[
    "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php", "sh", "bash", "zsh",
    "ksh", "dash", "fish", "awk",
];

const INLINE_CODE_FLAGS: &[&str] = &["-c", "-e", "-r", "--command", "--exec"];

/// Builtins that re-parse string arguments as shell code, regardless of
/// quoting. They launder substitution past the context-aware substitution
/// gate (`'$(rm -rf /)'` is literal as a string but executable once `eval`
/// re-parses it). Blocked in ReadOnly + WorkspaceWrite modes, same posture
/// as `python -c` / `bash -c`.
///
/// `.` is the POSIX-portable spelling of `source`.
const CODE_LAUNDERING_COMMANDS: &[&str] = &["eval", "source", "."];

#[must_use]
pub fn validate_read_only(command: &str, mode: PermissionMode) -> ValidationResult {
    if mode != PermissionMode::ReadOnly {
        return ValidationResult::Allow;
    }

    // Industrial Standard Mitigation: Proper shell splitting that respects quotes
    let parts = shell_split(command);

    // Token-prefix scan for dangerous env-var assignments. Runs over the
    // post-quote-strip tokens, so quoting tricks (`L'D'_PRELOAD=...`) are
    // caught and benign filename matches are not.
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
    }

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

    // Interpreter-laundering check lives in `validate_bash_command`'s
    // early gate (see `contains_interpreter_with_inline_code`); it now
    // covers both ReadOnly and WorkspaceWrite modes, so no per-segment
    // check is needed here.

    None
}

/// Simple shell splitter that respects single and double quotes.
fn shell_split(s: &str) -> Vec<String> {
    // Quoted-delimiter here-doc bodies (`<<'EOF'`, `<<"EOF"`, `<<-'EOF'`)
    // are literal text that the shell never tokenises as commands or
    // redirections. Mask their bytes so the tokenisation pass below never
    // sees `> ../foo` inside a commit message body as a real redirect.
    // Symmetric with how `contains_command_substitution` skips the same
    // shape via `skip_literal_heredoc_body`.
    let masked = mask_literal_heredoc_bodies(s);
    let s = masked.as_str();

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
            ' ' | '\t' if !in_single_quote && !in_double_quote => {
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
            }
            '\n' | '\r' if !in_single_quote && !in_double_quote => {
                // Unquoted newline / carriage return is a statement
                // terminator in bash. Treat it like `;` so each statement
                // reaches `check_command_segment` and the write/read-target
                // scans, matching how `sh -c` will actually execute it.
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
                parts.push(";".to_string());
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
            '<' if !in_single_quote && !in_double_quote => {
                // Split on unquoted `<` so glued forms like `cat</etc/shadow`
                // reach the read-target scan. Coalesce `<<` / `<<<` so
                // here-doc and here-string tokens stay recognizable.
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
                if chars.peek() == Some(&'<') {
                    let _ = chars.next();
                    if chars.peek() == Some(&'<') {
                        let _ = chars.next();
                        parts.push("<<<".to_string());
                    } else {
                        parts.push("<<".to_string());
                    }
                } else {
                    parts.push("<".to_string());
                }
            }
            '>' if !in_single_quote && !in_double_quote => {
                // Split on unquoted `>` so glued forms like `tee>/etc/passwd`
                // reach the write-target scan. Coalesce `>>` (append). `>&`
                // remains two tokens (`>` then `&`); the redirection-target
                // collector already skips `&`-prefixed next tokens.
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
                if chars.peek() == Some(&'>') {
                    let _ = chars.next();
                    parts.push(">>".to_string());
                } else {
                    parts.push(">".to_string());
                }
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

/// Detect command-substitution constructs whose inner command cannot be
/// safely validated by this layer:
///   * `$(...)`  — POSIX command substitution
///   * `` `...` `` — backtick command substitution
///   * `<(...)`  — process substitution (input)
///   * `>(...)`  — process substitution (output)
///
/// Honours shell quoting context. Substitution is only flagged when the
/// shell would actually evaluate it:
///   * Single-quoted strings (`'...'`) suppress all substitution.
///   * Double-quoted strings (`"..."`) still expand `$(...)` and backticks.
///   * Heredocs with a quoted delimiter (`<<'EOF'`, `<<"EOF"`, `<<-'EOF'`)
///     have a literal body and suppress substitution.
///   * Heredocs with an unquoted delimiter (`<<EOF`) expand their body, so
///     substitution inside is flagged.
///   * Backslash-escaped `\$` outside single quotes is literal.
///
/// Parameter expansion (`${VAR}`) and bare `$VAR` are intentionally NOT
/// flagged — they expand to a value, not to a separately-executed command,
/// and are common in legitimate workflows.
/// Recognise the safe substitution idiom `$(cat <<'DELIM' BODY DELIM)`
/// (and the `<<"DELIM"` / `<<-'DELIM'` / `<<-"DELIM"` variants).
///
/// `$(...)` is normally refused because the shell evaluates the inner
/// command before the outer command ever runs, and the validator has no
/// way to reason about that inner program in general. But when the inner
/// program is exactly a `cat` reading a quoted-delimiter here-doc — no
/// other arguments, no extra commands, no chaining — the substitution
/// reduces to "emit the literal heredoc body as a string." That cannot
/// reach the filesystem, network, or any other side effect; the worst
/// it can do is hand a string to the outer command.
///
/// Closes the recurring Claude Code dogfood friction: the system-prompt
/// recommended commit form is
/// `git commit -m "$(cat <<'EOF' ... EOF)"`. Before this idiom recogniser
/// the validator denied every such call and Claude fell back to
/// `git commit -F -` after a friction roundtrip; the dogfood JSONL had
/// 12 of these denies between 2026-05-20 and 2026-05-27 with the same
/// retry shape every time.
///
/// `paren_pos` is the index of the `(` that opens the substitution. On a
/// match the function returns the byte index immediately after the
/// closing `)` so the substitution walker can resume from there. On any
/// deviation from the exact safe shape — different inner command,
/// additional arguments, unquoted heredoc delimiter, trailing
/// `; rm -rf /`, etc. — the function returns `None` and the substitution
/// walker falls through to its normal refusal.
fn safe_cat_heredoc_substitution_end(bytes: &[u8], paren_pos: usize) -> Option<usize> {
    let n = bytes.len();
    if paren_pos + 1 >= n {
        return None;
    }
    let mut i = paren_pos + 1; // step past `(`

    // Leading whitespace inside the substitution.
    while i < n && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'\n') {
        i += 1;
    }

    // Expect the literal command word "cat" followed by inline whitespace.
    // Reject "cats", "catalog", "catx" etc. by requiring whitespace right
    // after the 'cat' bytes.
    if i + 3 >= n || &bytes[i..i + 3] != b"cat" {
        return None;
    }
    let after_cat = bytes[i + 3];
    if !(after_cat == b' ' || after_cat == b'\t') {
        return None;
    }
    i += 3;
    while i < n && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }

    // Expect `<<` (optionally `<<-` for the indented form) and then a
    // quoted delimiter — `skip_literal_heredoc_body` only accepts the
    // quoted form, which is what makes the body literal text.
    if i + 1 >= n || bytes[i] != b'<' || bytes[i + 1] != b'<' {
        return None;
    }
    i += 2;
    if i < n && bytes[i] == b'-' {
        i += 1;
    }
    while i < n && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    let body_end = skip_literal_heredoc_body(bytes, i)?;
    i = body_end;

    // After the heredoc body the only legal next token is the closing `)`.
    // Whitespace (incl. newline) between is fine; anything else — `;`,
    // `&&`, another command — means more shell happens inside the
    // substitution and the safe-idiom guarantee no longer holds.
    while i < n && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'\n') {
        i += 1;
    }
    if i >= n || bytes[i] != b')' {
        return None;
    }
    Some(i + 1)
}

fn contains_command_substitution(command: &str) -> Option<&'static str> {
    let bytes = command.as_bytes();
    let n = bytes.len();
    let mut i = 0;

    while i < n {
        let c = bytes[i];

        // Backslash escape outside any quote: skip the next byte.
        if c == b'\\' && i + 1 < n {
            i += 2;
            continue;
        }

        // Single-quoted region: bash treats everything inside as literal.
        if c == b'\'' {
            i += 1;
            while i < n && bytes[i] != b'\'' {
                i += 1;
            }
            i += 1; // skip closing quote (or step past EOF)
            continue;
        }

        // Double-quoted region: substitution is STILL active. Scan inside
        // for `$(` and backticks, honouring `\` escapes.
        if c == b'"' {
            i += 1;
            while i < n && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < n {
                    i += 2;
                    continue;
                }
                if bytes[i] == b'$' && i + 1 < n && bytes[i + 1] == b'(' {
                    if let Some(end) = safe_cat_heredoc_substitution_end(bytes, i + 1) {
                        i = end;
                        continue;
                    }
                    return Some("$(");
                }
                if bytes[i] == b'`' {
                    return Some("`");
                }
                i += 1;
            }
            i += 1;
            continue;
        }

        // Heredoc: `<<` or `<<-` followed by a delimiter token. If the
        // delimiter is quoted, the body is literal — skip past it.
        if c == b'<' && i + 1 < n && bytes[i + 1] == b'<' {
            let mut j = i + 2;
            if j < n && bytes[j] == b'-' {
                j += 1;
            }
            while j < n && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if let Some(skip_to) = skip_literal_heredoc_body(bytes, j) {
                i = skip_to;
                continue;
            }
            // Unquoted (or unrecognised) heredoc: let the main loop scan
            // the body. Step past the `<<` and continue.
            i += 2;
            continue;
        }

        // Process substitution: `<(` or `>(` outside any quote.
        if (c == b'<' || c == b'>') && i + 1 < n && bytes[i + 1] == b'(' {
            return Some(if c == b'<' { "<(" } else { ">(" });
        }

        // Top-level substitution.
        if c == b'$' && i + 1 < n && bytes[i + 1] == b'(' {
            if let Some(end) = safe_cat_heredoc_substitution_end(bytes, i + 1) {
                i = end;
                continue;
            }
            return Some("$(");
        }
        if c == b'`' {
            return Some("`");
        }

        i += 1;
    }

    None
}

/// Detect bash code-laundering builtins (`eval`, `source`, `.`) anywhere
/// in the command. Splits on shell statement separators so a laundered
/// builtin in any pipeline segment is caught. Skips leading variable
/// assignments (`VAR=val eval ...`) before reading the first command word.
///
/// Returns the matched builtin name on hit, `None` otherwise.
/// Segment-aware scan for `python3 -c '...'` / `perl -e '...'` /
/// `bash -c '...'` / etc. Matches the scope of the substitution gate
/// (ReadOnly + WorkspaceWrite): the inner program is opaque to the
/// validator, so any inline-code invocation has to be refused before
/// the policy/path checks would even see the destructive payload.
///
/// Walks segments split on `|` / `;` / `&&` / `||` / `&`, skips leading
/// `FOO=bar` variable-assignment prefixes (parity with
/// `contains_code_laundering_command`), unwraps one `sudo` layer, then
/// checks `first_command` against `INLINE_CODE_INTERPRETERS`. Returns
/// `Some((interpreter, flag))` on the first hit.
fn contains_interpreter_with_inline_code(command: &str) -> Option<(String, String)> {
    let parts = shell_split(command);

    let scan = |segment: &[&String]| -> Option<(String, String)> {
        // Skip variable-assignment prefixes, then optionally one `sudo`.
        let mut idx = 0;
        while idx < segment.len() {
            let token = segment[idx];
            if token.contains('=')
                && token
                    .as_bytes()
                    .iter()
                    .take_while(|&&b| b != b'=')
                    .all(|&b| b.is_ascii_alphanumeric() || b == b'_')
            {
                idx += 1;
                continue;
            }
            break;
        }
        if idx < segment.len() && segment[idx].as_str() == "sudo" {
            idx += 1;
        }

        let first = segment.get(idx)?;
        if !INLINE_CODE_INTERPRETERS.contains(&first.as_str()) {
            return None;
        }
        for arg in &segment[idx + 1..] {
            if INLINE_CODE_FLAGS.contains(&arg.as_str()) {
                return Some((first.as_str().to_string(), arg.as_str().to_string()));
            }
        }
        None
    };

    let mut segment: Vec<&String> = Vec::new();
    for part in &parts {
        if part == "|" || part == ";" || part == "&&" || part == "||" || part == "&" {
            if let Some(hit) = scan(&segment) {
                return Some(hit);
            }
            segment.clear();
        } else {
            segment.push(part);
        }
    }
    scan(&segment)
}

fn contains_code_laundering_command(command: &str) -> Option<&'static str> {
    let parts = shell_split(command);
    let mut segment: Vec<&String> = Vec::new();

    let flush = |segment: &[&String]| -> Option<&'static str> {
        for token in segment {
            // Skip variable-assignment prefixes: `FOO=bar eval ...`.
            if token.contains('=')
                && token
                    .as_bytes()
                    .iter()
                    .take_while(|&&b| b != b'=')
                    .all(|&b| b.is_ascii_alphanumeric() || b == b'_')
            {
                continue;
            }
            for &builtin in CODE_LAUNDERING_COMMANDS {
                if token.as_str() == builtin {
                    return Some(builtin);
                }
            }
            // First non-assignment token decides the segment's command.
            return None;
        }
        None
    };

    for part in &parts {
        if part == "|" || part == ";" || part == "&&" || part == "||" || part == "&" {
            if let Some(hit) = flush(&segment) {
                return Some(hit);
            }
            segment.clear();
        } else {
            segment.push(part);
        }
    }
    if let Some(hit) = flush(&segment) {
        return Some(hit);
    }
    None
}

/// If `bytes[start..]` begins with a quoted heredoc delimiter
/// (`'DELIM'` or `"DELIM"`), find the body terminator and return the byte
/// index immediately after it. Returns `None` for unquoted or malformed
/// delimiters so the caller falls back to ordinary scanning.
/// Pre-tokenisation pass that replaces the bytes inside the body of any
/// quoted-delimiter here-doc (`<<'DELIM'`, `<<"DELIM"`, plus the `<<-`
/// indented forms) with spaces. The shell never executes or expands a
/// quoted-delim heredoc body, so a `>` / `<` / `|` inside one is literal
/// text — not a real redirection or pipe.
///
/// Bug being closed: before this pass, `shell_split` saw the body of a
/// `git commit -F - <<'EOF' ... EOF` heredoc as code, so a commit message
/// that happened to contain a literal `> ../escape.txt` tripped the
/// relative-parent-escape gate. Symmetric with the heredoc skip already
/// performed by `contains_command_substitution` via
/// `skip_literal_heredoc_body`.
///
/// Unquoted-delimiter heredocs (`<<EOF`) are left alone: bash does
/// parameter and command substitution inside their bodies, so the
/// substitution scanner needs to see them. A literal `>` inside an
/// unquoted heredoc body is still never a real redirect either, but we
/// keep that out of scope until we see real false positives — the
/// conservative behaviour mirrors `skip_literal_heredoc_body`.
fn mask_literal_heredoc_bodies(command: &str) -> String {
    let bytes = command.as_bytes();
    let n = bytes.len();
    let mut out = bytes.to_vec();
    let mut i = 0;
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    while i < n {
        let c = bytes[i];

        if in_single_quote {
            if c == b'\'' {
                in_single_quote = false;
            }
            i += 1;
            continue;
        }
        if in_double_quote {
            if c == b'\\' && i + 1 < n {
                i += 2;
                continue;
            }
            if c == b'"' {
                in_double_quote = false;
            }
            i += 1;
            continue;
        }

        if c == b'\\' && i + 1 < n {
            i += 2;
            continue;
        }
        if c == b'\'' {
            in_single_quote = true;
            i += 1;
            continue;
        }
        if c == b'"' {
            in_double_quote = true;
            i += 1;
            continue;
        }

        // `<<` outside any quote: candidate here-doc operator.
        if c == b'<' && i + 1 < n && bytes[i + 1] == b'<' {
            let mut j = i + 2;
            if j < n && bytes[j] == b'-' {
                j += 1;
            }
            while j < n && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            // Only quoted delimiters get masked (see doc-comment).
            if j < n && (bytes[j] == b'\'' || bytes[j] == b'"') {
                if let Some(body_end) = skip_literal_heredoc_body(bytes, j) {
                    // Recompute body_start: after the newline that closes
                    // the `<<...DELIM` opening line.
                    let quote = bytes[j];
                    let delim_start = j + 1;
                    let mut delim_end = delim_start;
                    while delim_end < n && bytes[delim_end] != quote {
                        delim_end += 1;
                    }
                    let mut body_start = delim_end.saturating_add(1);
                    while body_start < n && bytes[body_start] != b'\n' {
                        body_start += 1;
                    }
                    if body_start < n {
                        body_start += 1;
                    }
                    // Replace every byte in the body (including newlines)
                    // with a single space. Newlines inside a heredoc body
                    // are never statement separators, so masking them is
                    // accurate and removes a class of spurious `\n→;`
                    // injections downstream in `shell_split`.
                    let end = body_end.min(n);
                    if body_start < end {
                        out[body_start..end].fill(b' ');
                    }
                    i = body_end;
                    continue;
                }
            }
        }

        i += 1;
    }

    // SAFETY: input was valid UTF-8 (`&str`). We only ever write the ASCII
    // byte 0x20 (space) into positions inside masked heredoc bodies. We
    // never write into the middle of a multi-byte sequence in a way that
    // breaks UTF-8: an entire run of body bytes becomes ASCII spaces, and
    // bytes outside any masked range are left untouched. The result is
    // therefore guaranteed valid UTF-8.
    String::from_utf8(out).expect("masking preserves UTF-8 validity")
}

fn skip_literal_heredoc_body(bytes: &[u8], start: usize) -> Option<usize> {
    let n = bytes.len();
    if start >= n {
        return None;
    }
    let quote = match bytes[start] {
        b'\'' => b'\'',
        b'"' => b'"',
        _ => return None,
    };

    let delim_start = start + 1;
    let mut delim_end = delim_start;
    while delim_end < n && bytes[delim_end] != quote {
        delim_end += 1;
    }
    if delim_end >= n {
        // Unterminated quoted delimiter — treat as literal-until-EOF so
        // the caller doesn't flag substitution-looking bytes the user
        // clearly intended as content.
        return Some(n);
    }
    let delim = &bytes[delim_start..delim_end];
    if delim.is_empty() {
        return None;
    }

    // Body starts after the newline that closes the `<<...DELIM` line.
    let mut body_start = delim_end + 1;
    while body_start < n && bytes[body_start] != b'\n' {
        body_start += 1;
    }
    if body_start >= n {
        return Some(n);
    }
    body_start += 1;

    // Walk lines until we find one whose trimmed content equals `delim`.
    let mut line_start = body_start;
    while line_start < n {
        let mut line_end = line_start;
        while line_end < n && bytes[line_end] != b'\n' {
            line_end += 1;
        }
        // `<<-` form allows leading tabs on the closing delimiter line.
        let trimmed_start = {
            let mut t = line_start;
            while t < line_end && bytes[t] == b'\t' {
                t += 1;
            }
            t
        };
        if &bytes[trimmed_start..line_end] == delim {
            return Some(line_end);
        }
        if line_end >= n {
            return Some(n);
        }
        line_start = line_end + 1;
    }
    Some(n)
}

pub fn validate_bash_command(
    command: &str,
    mode: PermissionMode,
    workspace_path: &Path,
    escape_paths: &[String],
) -> ValidationResult {
    if mode == PermissionMode::Blocked {
        return ValidationResult::Block {
            reason: "tool is in blocked mode".to_string(),
        };
    }
    if mode == PermissionMode::Allow {
        return ValidationResult::Allow;
    }

    // Gate substitution before policy checks: if a substituted command or
    // path target is opaque to the validator, no downstream policy decision
    // can be trusted. Matches the scope of `validate_paths` (ReadOnly +
    // WorkspaceWrite); DangerFullAccess / Prompt accept opaque payloads by
    // design.
    if matches!(
        mode,
        PermissionMode::ReadOnly | PermissionMode::WorkspaceWrite
    ) {
        if let Some(pat) = contains_command_substitution(command) {
            return ValidationResult::Block {
                reason: format!(
                    "Command contains shell substitution '{pat}' whose inner command cannot be validated"
                ),
            };
        }
        if let Some(builtin) = contains_code_laundering_command(command) {
            return ValidationResult::Block {
                reason: format!(
                    "Builtin '{builtin}' re-parses its arguments as shell code and is not allowed"
                ),
            };
        }
        if let Some((interp, flag)) = contains_interpreter_with_inline_code(command) {
            return ValidationResult::Block {
                reason: format!(
                    "Interpreter '{interp}' invoked with inline-code flag '{flag}' is not allowed in this mode"
                ),
            };
        }
    }

    let res = validate_read_only(command, mode);
    if res != ValidationResult::Allow {
        return res;
    }

    let res = validate_paths(command, mode, workspace_path, escape_paths);
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
    escape_paths: &[String],
) -> ValidationResult {
    validate_bash_command(command, mode, _workspace, escape_paths)
}

pub fn validate_mode(command: &str, mode: PermissionMode) -> ValidationResult {
    validate_read_only(command, mode)
}

pub fn validate_paths(
    command: &str,
    mode: PermissionMode,
    workspace: &Path,
    escape_paths: &[String],
) -> ValidationResult {
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
            // Absolute path outside the workspace gets one last chance via the
            // policy-declared escape list. Relative `../` escape (below) does
            // not — that vector is always suspicious regardless of policy.
            if matches_escape_glob(candidate, escape_paths) {
                continue;
            }
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
            if matches_escape_glob(candidate, escape_paths) {
                continue;
            }
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

fn matches_escape_glob(candidate: &str, escape_paths: &[String]) -> bool {
    escape_paths.iter().any(|pat| {
        glob::Pattern::new(pat)
            .map(|g| g.matches(candidate))
            .unwrap_or(false)
    })
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
        "mv" | "cp" => {
            // Destination is the last non-flag arg; sources are read-only
            // and not aliased post-op, so they remain out of scope here.
            if let Some(last) = args.iter().rev().find(|token| {
                !token.starts_with('-') && !WRITE_REDIRECTIONS.contains(&token.as_str())
            }) {
                targets.push(last.clone());
            }
        }
        "ln" | "link" => {
            // Both `ln -s` (symlink) and `ln` / `link` (hardlink) bind the
            // created name to the source: symlinks follow the source for
            // future writes, hardlinks share its inode. Treat every non-flag
            // arg as a target so a workspace-internal link whose source
            // points outside the workspace is rejected (closes the
            // 2026-05-14 HIGH path-traversal-escape finding).
            targets.extend(
                args.iter()
                    .filter(|token| {
                        !token.starts_with('-') && !WRITE_REDIRECTIONS.contains(&token.as_str())
                    })
                    .cloned(),
            );
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
        shell_split, validate_bash_command, validate_paths, validate_read_only, PermissionMode,
        ValidationResult,
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
            &[],
        );
        assert_eq!(result, ValidationResult::Allow);
    }

    #[test]
    fn validate_paths_blocks_absolute_path_outside_workspace() {
        let result = validate_paths(
            "echo ok > /etc/passwd",
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
            &[],
        );
        assert!(matches!(result, ValidationResult::Block { .. }));
    }

    #[test]
    fn validate_paths_blocks_parent_dir_escape() {
        let result = validate_paths(
            "echo ok > ../outside.txt",
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
            &[],
        );
        assert!(matches!(result, ValidationResult::Block { .. }));
    }

    #[test]
    fn validate_paths_blocks_common_write_command_outside_workspace() {
        let result = validate_paths(
            "tee /etc/passwd",
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
            &[],
        );
        assert!(matches!(result, ValidationResult::Block { .. }));
    }

    #[test]
    fn validate_paths_escape_list_allows_listed_absolute_write() {
        // Absolute path outside workspace, but matches an escape glob → allow.
        let escape = vec!["/tmp/**".to_string()];
        let result = validate_paths(
            "echo ok > /tmp/scratch.md",
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
            &escape,
        );
        assert_eq!(result, ValidationResult::Allow);
    }

    #[test]
    fn validate_paths_escape_list_does_not_allow_relative_parent_escape() {
        // Even with an escape glob that would syntactically match the resolved
        // form, a relative `../` write is still rejected — the relative-escape
        // path is a different threat class.
        let escape = vec!["/**".to_string()];
        let result = validate_paths(
            "echo ok > ../outside.txt",
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
            &escape,
        );
        assert!(matches!(result, ValidationResult::Block { .. }));
    }

    #[test]
    fn validate_paths_escape_list_allows_listed_absolute_read() {
        // Read target symmetry: escape list also lets cat /tmp/... through.
        let escape = vec!["/tmp/**".to_string()];
        let result = validate_paths(
            "cat /tmp/scratch.md",
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
            &escape,
        );
        assert_eq!(result, ValidationResult::Allow);
    }

    #[test]
    fn validate_paths_escape_list_still_blocks_unlisted_absolute() {
        // Path outside workspace and outside the escape list → still blocked.
        let escape = vec!["/tmp/**".to_string()];
        let result = validate_paths(
            "echo ok > /etc/passwd",
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
            &escape,
        );
        assert!(matches!(result, ValidationResult::Block { .. }));
    }

    // ── heredoc body literalness (quoting-aware shell_split) ────────────────

    #[test]
    fn shell_split_masks_quoted_heredoc_body() {
        // Tokens inside a `<<'EOF'` body are literal text, not shell syntax.
        // After masking, the body collapses to whitespace and the `>` /
        // `../escape.txt` from inside the body produce no tokens.
        let parts = shell_split("cat <<'EOF'\necho > ../escape.txt\nEOF\n");
        assert!(
            !parts.iter().any(|t| t == ">"),
            "`>` from heredoc body must not survive tokenization, got {parts:?}"
        );
        assert!(
            !parts.iter().any(|t| t == "../escape.txt"),
            "literal `../escape.txt` from heredoc body must not survive, got {parts:?}"
        );
    }

    #[test]
    fn validate_paths_allows_parent_escape_inside_quoted_heredoc_body() {
        // The exact dogfood bug from 2026-05-20: a commit message body that
        // happens to contain `> ../foo` was being parsed as a real relative
        // parent-dir escape redirect. With masking, the body is invisible to
        // the redirect collector.
        let cmd = "git commit -F - <<'COMMITMSG'\nfix: example\n\nexample text mentions echo > ../escape.txt\nCOMMITMSG\n";
        let result = validate_paths(
            cmd,
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
            &[],
        );
        assert_eq!(result, ValidationResult::Allow);
    }

    #[test]
    fn validate_paths_allows_absolute_write_inside_quoted_heredoc_body() {
        // Same shape, but the body literal is an absolute outside-workspace
        // path. Still must not fire — the shell never opens a file here.
        let cmd = "cat <<'EOF'\ndocs reference: echo > /etc/passwd\nEOF\n";
        let result = validate_paths(
            cmd,
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
            &[],
        );
        assert_eq!(result, ValidationResult::Allow);
    }

    #[test]
    fn validate_paths_blocks_real_redirect_outside_heredoc_body() {
        // Regression: a real `>` redirect outside any heredoc must still
        // block. Combines a real out-of-workspace write with a heredoc whose
        // body contains a fake one — only the real redirect should fire.
        let cmd = "echo ok > /etc/passwd && cat <<'EOF'\nbody mentions echo > /etc/shadow\nEOF\n";
        let result = validate_paths(
            cmd,
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
            &[],
        );
        match result {
            ValidationResult::Block { reason } => {
                assert!(
                    reason.contains("/etc/passwd"),
                    "real redirect to /etc/passwd should be the cited target, got: {reason}"
                );
            }
            other => panic!("expected Block on real redirect, got {other:?}"),
        }
    }

    #[test]
    fn validate_paths_blocks_redirect_outside_unquoted_heredoc_body() {
        // Unquoted-delimiter heredocs are not masked (matches
        // `skip_literal_heredoc_body`'s contract): the substitution scanner
        // still needs to see those bodies. A real `>` outside the heredoc on
        // the same command line must therefore still block.
        let cmd = "echo ok > /etc/passwd <<EOF\nfiller body\nEOF\n";
        let result = validate_paths(
            cmd,
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
            &[],
        );
        assert!(matches!(result, ValidationResult::Block { .. }));
    }

    // ── safe-cat-heredoc substitution idiom (dogfood friction polish) ──────

    #[test]
    fn validate_bash_allows_cat_heredoc_substitution_inside_double_quotes() {
        // The Claude Code system-prompt recommended commit form. Was the top
        // recurring deny on the dogfood JSONL (12 hits, 2026-05-20..27).
        let cmd = "git commit -m \"$(cat <<'EOF'\nfeat: thing\n\nbody\nEOF\n)\"";
        let result = validate_bash_command(
            cmd,
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
            &[],
        );
        assert_eq!(result, ValidationResult::Allow, "got {result:?}");
    }

    #[test]
    fn validate_bash_allows_top_level_cat_heredoc_substitution() {
        // Symmetric to the double-quoted case: `$(cat <<'EOF' ... EOF)`
        // with no surrounding quotes is still the same safe shape.
        let cmd = "git commit -m $(cat <<'EOF'\nbody\nEOF\n)";
        let result = validate_bash_command(
            cmd,
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
            &[],
        );
        assert_eq!(result, ValidationResult::Allow, "got {result:?}");
    }

    #[test]
    fn validate_bash_allows_cat_heredoc_with_double_quoted_delimiter() {
        // `<<"EOF"` is also a literal-body heredoc; idiom recognition must
        // mirror skip_literal_heredoc_body, which accepts both quote chars.
        let cmd = "git commit -m \"$(cat <<\"EOF\"\nbody\nEOF\n)\"";
        let result = validate_bash_command(
            cmd,
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
            &[],
        );
        assert_eq!(result, ValidationResult::Allow, "got {result:?}");
    }

    #[test]
    fn validate_bash_allows_cat_indented_heredoc_substitution() {
        // `<<-` strips leading tabs on the closing delimiter line; the body
        // is still literal, so the same safe-idiom guarantee applies.
        let cmd = "echo \"$(cat <<-'EOF'\n\tbody\n\tEOF\n)\"";
        let result = validate_bash_command(
            cmd,
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
            &[],
        );
        assert_eq!(result, ValidationResult::Allow, "got {result:?}");
    }

    #[test]
    fn validate_bash_still_denies_unquoted_heredoc_substitution() {
        // Without quotes on the delimiter the shell expands `$(...)` /
        // backticks inside the body before piping to stdin; the safe-idiom
        // guarantee no longer holds.
        let cmd = "echo \"$(cat <<EOF\nbody\nEOF\n)\"";
        let result = validate_bash_command(
            cmd,
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
            &[],
        );
        assert!(
            matches!(result, ValidationResult::Block { .. }),
            "expected Block, got {result:?}"
        );
    }

    #[test]
    fn validate_bash_still_denies_cat_with_file_argument() {
        // The idiom only allows the heredoc form. A bare `$(cat /etc/passwd)`
        // would let the substitution read an arbitrary file and inject it
        // into the outer command; refuse.
        let cmd = "git commit -m \"$(cat /etc/passwd)\"";
        let result = validate_bash_command(
            cmd,
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
            &[],
        );
        assert!(
            matches!(result, ValidationResult::Block { .. }),
            "expected Block, got {result:?}"
        );
    }

    #[test]
    fn validate_bash_still_denies_substitution_with_chained_command_after_heredoc() {
        // A trailing `; <cmd>` after the heredoc means more shell happens
        // inside `$(...)`. Reject — the safe-idiom guarantee was "exactly
        // `cat` + heredoc + nothing else."
        let cmd = "echo \"$(cat <<'EOF'\nx\nEOF\n; touch /tmp/pwned)\"";
        let result = validate_bash_command(
            cmd,
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
            &[],
        );
        assert!(
            matches!(result, ValidationResult::Block { .. }),
            "expected Block, got {result:?}"
        );
    }

    #[test]
    fn validate_bash_still_denies_non_cat_substitution() {
        // The whitelist is strictly the word "cat"; `printf`, `date`, etc.
        // remain refused so the gate doesn't silently widen.
        let cmd = "echo \"$(date)\"";
        let result = validate_bash_command(
            cmd,
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
            &[],
        );
        assert!(
            matches!(result, ValidationResult::Block { .. }),
            "expected Block, got {result:?}"
        );
    }

    #[test]
    fn validate_bash_still_denies_catx_prefix_match() {
        // Defends the strict word boundary: a command like `catx <<'EOF'`
        // happens to start with the three bytes "cat" but is not the `cat`
        // builtin. Must still fail the idiom check.
        let cmd = "echo \"$(catx <<'EOF'\nx\nEOF\n)\"";
        let result = validate_bash_command(
            cmd,
            PermissionMode::WorkspaceWrite,
            Path::new("/workspace"),
            &[],
        );
        assert!(
            matches!(result, ValidationResult::Block { .. }),
            "expected Block, got {result:?}"
        );
    }
}
