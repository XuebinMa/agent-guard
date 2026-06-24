//! Shell tokenisation, heredoc masking, and injection-detection helpers.

use super::tables::{CODE_LAUNDERING_COMMANDS, INLINE_CODE_FLAGS, INLINE_CODE_INTERPRETERS};
use super::wrappers::unwrap_command_wrappers;

/// Simple shell splitter that respects single and double quotes.
pub(crate) fn shell_split(s: &str) -> Vec<String> {
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
                // reach the write-target scan. Coalesce the multi-char write
                // redirections `>>` (append), `>|` (noclobber-override
                // force-write), and `>&` (redirect stdout+stderr to the
                // following file, or duplicate a fd when the target is a
                // number) into single tokens so their trailing operator char is
                // not mistaken for a pipeline separator (`|`) or a
                // background/segment separator (`&`) — either of which strands
                // the write target in a fresh segment and bypasses the
                // write-target scan.
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
                if chars.peek() == Some(&'>') {
                    let _ = chars.next();
                    parts.push(">>".to_string());
                } else if chars.peek() == Some(&'|') {
                    // `>|` forces a write even under `set -o noclobber`. Coalesce
                    // it so the trailing `|` is not treated as a pipeline
                    // separator — otherwise the write target after `>|` lands in
                    // the next segment and escapes the scan (workspace escape).
                    let _ = chars.next();
                    parts.push(">|".to_string());
                } else if chars.peek() == Some(&'&') {
                    // `>&file` (non-numeric target) redirects both stdout and
                    // stderr to `file` in bash. Coalesce so the trailing `&` is
                    // not treated as a background/segment separator — otherwise
                    // the file target lands in the next segment and escapes the
                    // scan. fd-duplication forms (`>&2`, `2>&1`) collect the
                    // numeric token as a harmless relative-path "target" that
                    // never trips the workspace check.
                    let _ = chars.next();
                    parts.push(">&".to_string());
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

pub(crate) fn extract_first_command(s: &str) -> String {
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

pub(crate) fn contains_command_substitution(command: &str) -> Option<&'static str> {
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
pub(crate) fn contains_interpreter_with_inline_code(command: &str) -> Option<(String, String)> {
    let parts = shell_split(command);

    let scan = |segment: &[&String]| -> Option<(String, String)> {
        let rest = unwrap_command_wrappers(segment);

        let first = rest.first()?;
        if !INLINE_CODE_INTERPRETERS.contains(&first.as_str()) {
            return None;
        }
        for arg in &rest[1..] {
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

pub(crate) fn contains_code_laundering_command(command: &str) -> Option<&'static str> {
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
    match String::from_utf8(out) {
        Ok(masked) => masked,
        // Unreachable given the invariant above. This is a security-critical
        // path, so fall back to a lossy decode rather than panic if masking
        // ever writes into the middle of a multi-byte sequence.
        Err(err) => String::from_utf8_lossy(err.as_bytes()).into_owned(),
    }
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
