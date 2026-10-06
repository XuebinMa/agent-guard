//! Shell syntax front-end backed by a real grammar (tree-sitter-bash).
//!
//! # Why this exists
//!
//! The hand-rolled tokenizer in [`super::tokenize`] splits a command on
//! `| ; && || &` and treats the first token of each segment as the command
//! word. Shell grammar is not flat, so every construct that nests commands —
//! `{ …; }`, `( … )`, `if/then`, `while/do`, `for/do`, `case`, function
//! bodies — presents a keyword or a brace as the "command word", and the real
//! command underneath is never classified. That is one bug class, and it has
//! been patched roughly fifteen times, once per syntax form.
//!
//! This module removes the class instead of the instances: parse with the
//! grammar, then walk the tree. A command is only ever classified from a
//! `command` node, so nesting cannot hide one.
//!
//! # Fail-closed contract
//!
//! The walker recognises an explicit allowlist of node kinds
//! (`STRUCTURAL_KINDS`). Anything else — a syntax error, or a construct this
//! module has not been taught — yields [`ShellParse::TooComplex`], which
//! restricted modes must treat as a denial. Novel syntax therefore fails
//! closed by default; the previous design failed open by default, which is
//! why each new form needed its own patch.
//!
//! The `grammar_kinds_are_all_classified` test pins every node kind the linked
//! grammar can emit, so a grammar upgrade that introduces a kind is a test
//! failure rather than a silent behaviour change.

use tree_sitter::{Node, Parser};

/// Node kinds the walker understands and traverses.
///
/// Adding a kind here is a security decision: it asserts that the walker
/// reaches every command nested inside that construct. Do not add a kind
/// without extending the walker and the corpus together.
const STRUCTURAL_KINDS: &[&str] = &[
    // Program structure and sequencing.
    "program",
    "list",
    "pipeline",
    "subshell",
    "compound_statement",
    "negated_command",
    "redirected_statement",
    "command",
    "command_name",
    "command_substitution",
    "process_substitution",
    "function_definition",
    // Control flow.
    "if_statement",
    "elif_clause",
    "else_clause",
    "while_statement",
    "until_statement",
    "for_statement",
    "c_style_for_statement",
    "case_statement",
    "case_item",
    "do_group",
    "test_command",
    "unary_expression",
    "binary_expression",
    "declaration_command",
    "unset_command",
    "subscript",
    // Test and arithmetic expression forms. None of these is a command
    // position: they compute a value. A command reached through one (e.g.
    // `$(( $(cmd) ))`) still appears as its own `command_substitution` child
    // and is walked normally.
    "parenthesized_expression",
    "postfix_expression",
    "ternary_expression",
    "test_operator",
    // Words and values.
    "word",
    "string",
    "raw_string",
    "ansi_c_string",
    "translated_string",
    "string_content",
    "number",
    "concatenation",
    "simple_expansion",
    "expansion",
    "variable_name",
    "special_variable_name",
    "variable_assignment",
    "variable_assignments",
    "brace_expression",
    "array",
    "arithmetic_expansion",
    "extglob_pattern",
    "regex",
    // Redirection and heredocs.
    "file_redirect",
    "heredoc_redirect",
    // `<<< word` feeds a string on stdin. It names no file, and a command
    // substitution inside it is still a `command_substitution` child.
    "herestring_redirect",
    "heredoc_start",
    "heredoc_body",
    "heredoc_end",
    "heredoc_content",
    "file_descriptor",
    // Trivia.
    "comment",
];

/// Node kinds that are deliberately NOT understood. Encountering one is a
/// fail-closed rejection with a specific reason rather than a generic
/// "unknown construct", so operators get an actionable message.
const REJECTED_KINDS: &[(&str, &str)] = &[(
    "coprocess_statement",
    "a coprocess runs commands asynchronously in a subshell",
)];

/// One command position recovered from the syntax tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedCommand {
    /// The command word plus its arguments, as written.
    pub argv: Vec<String>,
    /// True when this command came from a command substitution or process
    /// substitution — its output is consumed by an enclosing command, but it
    /// still executes and still needs a decision of its own.
    pub nested: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ShellParse {
    /// Every construct in the input was recognised.
    Understood(Vec<ResolvedCommand>),
    /// The input contains a syntax error or a construct this module does not
    /// model. Restricted modes must deny.
    TooComplex(String),
}

/// Parse a shell command line and recover every command position in it.
pub(crate) fn parse_shell(command: &str) -> ShellParse {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .is_err()
    {
        return ShellParse::TooComplex("shell grammar unavailable".to_string());
    }

    let Some(tree) = parser.parse(command, None) else {
        return ShellParse::TooComplex("shell input could not be parsed".to_string());
    };

    if let Some(byte) = unquoted_control_byte(tree.root_node(), command) {
        return ShellParse::TooComplex(format!(
            "control character U+{byte:04X} outside literal text cannot be validated \
             consistently with the shell"
        ));
    }

    let mut walk = Walk {
        commands: Vec::new(),
        rejection: None,
        nesting: 0,
    };
    walk.visit(tree.root_node(), command);

    match walk.rejection {
        Some(reason) => ShellParse::TooComplex(reason),
        None => ShellParse::Understood(walk.commands),
    }
}

/// Literal regions in which a raw control byte is data, not shell whitespace.
const LITERAL_TEXT_KINDS: &[&str] = &[
    "string",
    "raw_string",
    "ansi_c_string",
    "translated_string",
    "string_content",
    "heredoc_body",
    "heredoc_content",
    "comment",
];

/// The grammar treats VT/FF/CR as whitespace while the executing shell can
/// treat them as word bytes, changing whether a following `#` is a comment.
/// Reject raw ASCII controls other than shell tab/newline outside literal
/// regions instead of deriving a decision from that ambiguous parse.
///
/// A substitution starts a new executable region. An outer quote or heredoc
/// cannot exempt its unquoted code; only literal nodes inside that region can.
fn unquoted_control_byte(root: Node, src: &str) -> Option<u8> {
    src.bytes().enumerate().find_map(|(index, byte)| {
        if !byte.is_ascii_control() || matches!(byte, b'\n' | b'\t') {
            return None;
        }
        let mut node = root.descendant_for_byte_range(index, index + 1);
        while let Some(current) = node {
            if matches!(
                current.kind(),
                "command_substitution" | "process_substitution"
            ) {
                break;
            }
            if LITERAL_TEXT_KINDS.contains(&current.kind()) {
                return None;
            }
            node = current.parent();
        }
        Some(byte)
    })
}

struct Walk {
    commands: Vec<ResolvedCommand>,
    rejection: Option<String>,
    nesting: usize,
}

impl Walk {
    fn visit(&mut self, node: Node, src: &str) {
        if self.rejection.is_some() {
            return;
        }

        if node.is_error() || node.is_missing() {
            self.rejection = Some("shell input is not valid syntax".to_string());
            return;
        }

        let kind = node.kind();

        // Bash truncates an ANSI-C quoted fragment at a decoded NUL. Keeping
        // that byte in argv would classify a different command/option. Other
        // undecodable ANSI-C escapes must not become guessed word values either.
        if kind == "ansi_c_string" {
            let value = node
                .utf8_text(src.as_bytes())
                .ok()
                .and_then(static_shell_word);
            match value {
                Some(value) if !value.contains('\0') => {}
                _ => {
                    self.rejection = Some(
                        "ANSI-C quoted word contains a NUL or an unsupported escape".to_string(),
                    );
                    return;
                }
            }
        }

        if let Some((_, why)) = REJECTED_KINDS.iter().find(|(name, _)| *name == kind) {
            self.rejection = Some(format!("unsupported shell construct `{kind}`: {why}"));
            return;
        }

        // Anonymous nodes are punctuation and keywords (`{`, `then`, `;`).
        // They carry no authority on their own; the named node that owns them
        // is what the walker classifies.
        if node.is_named() && !STRUCTURAL_KINDS.contains(&kind) {
            self.rejection = Some(format!("unrecognised shell construct `{kind}`"));
            return;
        }

        if kind == "command" {
            self.commands.push(ResolvedCommand {
                argv: argv_of(node, src),
                nested: self.nesting > 0,
            });
        }

        let nests = matches!(kind, "command_substitution" | "process_substitution");
        if nests {
            self.nesting += 1;
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.visit(child, src);
        }

        if nests {
            self.nesting -= 1;
        }
    }
}

/// Collect the argv of a `command` node: its name plus its argument words,
/// skipping the redirections and assignment prefixes that the grammar models
/// as separate children.
///
/// The shell deletes a backslash-newline pair before it reads words, so
/// `tou\⏎ch` is the one word `touch`. The grammar reads the pair as blank
/// space and yields two words. Two words with nothing else between them are
/// therefore joined back into the word the shell would run.
fn argv_of(node: Node, src: &str) -> Vec<String> {
    let mut argv: Vec<String> = Vec::new();
    let mut previous_word_end = None;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if !child.is_named() {
            continue;
        }
        match child.kind() {
            // Redirections name files, not arguments; the path gate reads
            // them separately.
            "file_redirect" | "heredoc_redirect" |
            // `FOO=bar cmd` — the assignment is a prefix, not the command.
            "variable_assignment" => {
                previous_word_end = None;
                continue;
            }
            _ => {}
        }
        if let Ok(text) = child.utf8_text(src.as_bytes()) {
            let value = word_value(text);
            let continues_previous = previous_word_end.is_some_and(|end| {
                src.get(end..child.start_byte())
                    .is_some_and(is_line_continuation_gap)
            });
            match argv.last_mut() {
                Some(previous) if continues_previous => previous.push_str(&value),
                _ => argv.push(value),
            }
            previous_word_end = Some(child.end_byte());
        }
    }
    argv
}

/// One or more continuations are deleted before shell word splitting. Any
/// actual whitespace left in the gap must still separate the words.
fn is_line_continuation_gap(mut gap: &str) -> bool {
    if gap.is_empty() {
        return false;
    }
    while !gap.is_empty() {
        if let Some(rest) = gap
            .strip_prefix("\\\n")
            .or_else(|| gap.strip_prefix("\\\r\n"))
        {
            gap = rest;
        } else {
            return false;
        }
    }
    true
}

/// One write to the shell environment that a later or child command can see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnvWrite {
    /// The variable name, as written.
    pub name: String,
    /// The assigned value when it is statically known. `None` means the value
    /// is dynamic, appended to, or inherited (`export NAME`), so no claim about
    /// it can be made.
    pub value: Option<String>,
}

/// Every environment write in a shell program, wherever it appears.
///
/// A `NAME=value` prefix changes the environment of the command it precedes,
/// and a statement-level assignment, `export`/`declare`, or `${NAME:=value}`
/// changes it for every later command (an assignment to an already-exported
/// name stays exported). `argv_of` drops all of these from command positions,
/// so they are recovered here for the gates that care about them. An input that
/// does not parse yields nothing; restricted modes reject it before asking.
pub(crate) fn environment_writes(command: &str) -> Vec<EnvWrite> {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(command, None) else {
        return Vec::new();
    };
    let mut writes = Vec::new();
    collect_environment_writes(tree.root_node(), command, &mut writes);
    writes
}

/// Shell aliases with runtime substitutions cannot be reduced to literal Git
/// argv, even when the grammar understands their shell structure.
pub(crate) fn has_dynamic_shell_words(command: &str) -> bool {
    fn dynamic(node: Node) -> bool {
        if matches!(
            node.kind(),
            "simple_expansion"
                | "expansion"
                | "command_substitution"
                | "process_substitution"
                | "arithmetic_expansion"
                | "translated_string"
        ) {
            return true;
        }
        let mut cursor = node.walk();
        let found = node.children(&mut cursor).any(dynamic);
        found
    }

    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .is_err()
    {
        return true;
    }
    match parser.parse(command, None) {
        Some(tree) => dynamic(tree.root_node()),
        None => true,
    }
}

fn collect_environment_writes(node: Node, src: &str, writes: &mut Vec<EnvWrite>) {
    match node.kind() {
        "declaration_command" => {
            // Declaration arguments may be quoted literals or adjacent nodes
            // (`export F'O'O=value`). Join only spans with no source gap.
            let mut cursor = node.walk();
            let mut span: Option<std::ops::Range<usize>> = None;
            for child in node.named_children(&mut cursor) {
                if let Some(previous) = span.as_mut() {
                    if previous.end == child.start_byte() {
                        previous.end = child.end_byte();
                        continue;
                    }
                    writes.extend(declaration_environment_write(&src[previous.clone()]));
                }
                span = Some(child.byte_range());
            }
            if let Some(span) = span {
                writes.extend(declaration_environment_write(&src[span]));
            }
        }
        "variable_assignment"
            if node.parent().map(|parent| parent.kind()) != Some("declaration_command") =>
        {
            if let Ok(text) = node.utf8_text(src.as_bytes()) {
                if let Some((name, value)) = text.split_once('=') {
                    let appended = name.ends_with('+');
                    let name = name.trim_end_matches('+');
                    let name = name.split('[').next().unwrap_or(name);
                    writes.push(EnvWrite {
                        name: name.to_string(),
                        value: if appended {
                            None
                        } else {
                            static_shell_word(value)
                        },
                    });
                }
            }
        }
        // `${NAME:=word}` / `${NAME=word}` assign when NAME is unset or empty.
        "expansion" => {
            if let Ok(text) = node.utf8_text(src.as_bytes()) {
                if let Some(name) = assigning_expansion_name(text) {
                    writes.push(EnvWrite { name, value: None });
                }
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_environment_writes(child, src, writes);
    }
}

fn declaration_environment_write(text: &str) -> Option<EnvWrite> {
    let (name, value) = if let Some(word) = static_shell_word(text) {
        word.split_once('=')
            .map_or((word.clone(), None), |(name, value)| {
                (name.to_string(), Some(value.to_string()))
            })
    } else {
        // A dynamic value still has a static assignment name. The '=' may be
        // inside a quoted argument, so complete the name's open quote only.
        let (prefix, _) = text.split_once('=')?;
        let name = static_shell_word(prefix)
            .or_else(|| static_shell_word(&format!("{prefix}'")))
            .or_else(|| static_shell_word(&format!("{prefix}\"")))?;
        (name, None)
    };
    let appended = name.ends_with('+');
    let name = name.trim_end_matches('+').split('[').next()?;
    if name.is_empty()
        || name.starts_with(|ch: char| ch.is_ascii_digit())
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return None;
    }
    Some(EnvWrite {
        name: name.to_string(),
        value: if appended { None } else { value },
    })
}

fn assigning_expansion_name(text: &str) -> Option<String> {
    let body = text.strip_prefix("${")?;
    let name_len = body
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .unwrap_or(body.len());
    let (name, rest) = body.split_at(name_len);
    (!name.is_empty() && (rest.starts_with(":=") || rest.starts_with('=')))
        .then(|| name.to_string())
}

/// The value of a word, with the shell's outer quoting removed.
///
/// `argv` must carry word *values*, not source spans: the tables and wrapper
/// grammars downstream compare against unquoted words, and a re-parsed payload
/// (`watch 'echo ok; rm /etc/passwd'`) is a command list, not a string
/// literal. Expansions inside the quotes are deliberately preserved, so
/// `"$CMD"` still reads as a dynamic command word.
fn word_value(text: &str) -> String {
    static_shell_word(text).unwrap_or_else(|| text.to_string())
}

/// Evaluate the parts of a shell word whose value is completely determined by
/// its source spelling. This deliberately handles the *whole* source span
/// rather than switching on the outer tree-sitter node kind: a command name is
/// wrapped in `command_name`, while `g""it`, `/usr/bin/"git"`, and `g\it` are
/// represented by still different child shapes even though Bash executes the
/// same static word.
///
/// Expansions and locale-translated strings return `None`; callers retain their
/// source spelling so the restricted-mode dynamic-command gates can reject
/// them instead of pretending to know their runtime value.
fn static_shell_word(text: &str) -> Option<String> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Quote {
        None,
        Single,
        Double,
        AnsiC,
    }

    fn push_ansi_escape(chars: &[char], index: &mut usize, out: &mut String) -> Option<()> {
        let escaped = *chars.get(*index)?;
        *index += 1;
        match escaped {
            'a' => out.push('\u{0007}'),
            'b' => out.push('\u{0008}'),
            'e' | 'E' => out.push('\u{001b}'),
            'f' => out.push('\u{000c}'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'v' => out.push('\u{000b}'),
            '\\' | '\'' | '"' | '?' => out.push(escaped),
            '\n' => {}
            'x' => {
                let start = *index;
                while *index < chars.len()
                    && *index - start < 2
                    && chars[*index].is_ascii_hexdigit()
                {
                    *index += 1;
                }
                if *index == start {
                    return None;
                }
                let digits: String = chars[start..*index].iter().collect();
                let byte = u8::from_str_radix(&digits, 16).ok()?;
                if !byte.is_ascii() {
                    return None;
                }
                out.push(char::from(byte));
            }
            'u' | 'U' => {
                let width = if escaped == 'u' { 4 } else { 8 };
                let start = *index;
                while *index < chars.len()
                    && *index - start < width
                    && chars[*index].is_ascii_hexdigit()
                {
                    *index += 1;
                }
                if *index == start {
                    return None;
                }
                let digits: String = chars[start..*index].iter().collect();
                let value = u32::from_str_radix(&digits, 16).ok()?;
                // Non-ASCII Unicode escapes depend on the executing shell's
                // locale. Refuse them rather than assuming UTF-8 word values.
                if value > 0x7f {
                    return None;
                }
                out.push(char::from_u32(value)?);
            }
            '0'..='7' => {
                let mut digits = String::from(escaped);
                while *index < chars.len() && digits.len() < 3 && matches!(chars[*index], '0'..='7')
                {
                    digits.push(chars[*index]);
                    *index += 1;
                }
                // Bash's octal escape is a byte, including wraparound at 256.
                let byte = (u32::from_str_radix(&digits, 8).ok()? & 0xff) as u8;
                if !byte.is_ascii() {
                    return None;
                }
                out.push(char::from(byte));
            }
            // Bash leaves unrecognised ANSI-C escapes implementation-defined
            // enough that treating them as a known executable would be unsafe.
            _ => return None,
        }
        Some(())
    }

    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut quote = Quote::None;
    let mut index = 0;

    while index < chars.len() {
        let ch = chars[index];
        index += 1;
        match quote {
            Quote::None => match ch {
                '\'' => quote = Quote::Single,
                '"' => quote = Quote::Double,
                '\\' => {
                    let escaped = *chars.get(index)?;
                    index += 1;
                    if escaped != '\n' {
                        out.push(escaped);
                    }
                }
                '$' if chars.get(index) == Some(&'\'') => {
                    index += 1;
                    quote = Quote::AnsiC;
                }
                // `$"..."` is locale translated; every other dollar form is
                // a runtime expansion. Neither has a statically knowable value.
                '$' | '`' => return None,
                _ => out.push(ch),
            },
            Quote::Single => {
                if ch == '\'' {
                    quote = Quote::None;
                } else {
                    out.push(ch);
                }
            }
            Quote::Double => match ch {
                '"' => quote = Quote::None,
                '\\' => {
                    let escaped = *chars.get(index)?;
                    index += 1;
                    if matches!(escaped, '$' | '`' | '"' | '\\') {
                        out.push(escaped);
                    } else if escaped == '\n' {
                        // A backslash-newline pair is removed before execution.
                    } else {
                        out.push('\\');
                        out.push(escaped);
                    }
                }
                '$' | '`' => return None,
                _ => out.push(ch),
            },
            Quote::AnsiC => match ch {
                '\'' => quote = Quote::None,
                '\\' => push_ansi_escape(&chars, &mut index, &mut out)?,
                _ => out.push(ch),
            },
        }
    }

    (quote == Quote::None).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commands(input: &str) -> Vec<Vec<String>> {
        match parse_shell(input) {
            ShellParse::Understood(cmds) => cmds.into_iter().map(|c| c.argv).collect(),
            ShellParse::TooComplex(reason) => panic!("expected a parse for {input:?}: {reason}"),
        }
    }

    /// The whole point: a command nested in any grouping construct is still
    /// recovered. These are the forms that each needed their own patch under
    /// the flat tokenizer.
    #[test]
    fn grouping_constructs_cannot_hide_a_command() {
        for input in [
            "touch /etc/x",
            "{ touch /etc/x; }",
            "( touch /etc/x )",
            "if true; then touch /etc/x; fi",
            "while true; do touch /etc/x; done",
            "until false; do touch /etc/x; done",
            "for i in 1 2; do touch /etc/x; done",
            "case y in y) touch /etc/x;; esac",
            "f() { touch /etc/x; }",
            "echo hi && { touch /etc/x; }",
            "echo hi\ntouch /etc/x",
            "! touch /etc/x",
        ] {
            let found = commands(input);
            assert!(
                found
                    .iter()
                    .any(|argv| argv.first().is_some_and(|w| w == "touch")),
                "`touch` must be recovered from {input:?}, got {found:?}"
            );
        }
    }

    #[test]
    fn command_substitution_is_recovered_as_its_own_command() {
        for input in ["echo $(touch /etc/x)", "echo `touch /etc/x`"] {
            let ShellParse::Understood(cmds) = parse_shell(input) else {
                panic!("expected a parse for {input:?}");
            };
            let inner = cmds
                .iter()
                .find(|c| c.argv.first().is_some_and(|w| w == "touch"))
                .unwrap_or_else(|| panic!("inner command missing for {input:?}: {cmds:?}"));
            assert!(inner.nested, "substituted command must be marked nested");
        }
    }

    #[test]
    fn literal_heredoc_body_is_not_a_command() {
        let found = commands("cat <<'EOF'\ntouch /etc/x\nEOF\n");
        assert_eq!(
            found,
            vec![vec!["cat".to_string()]],
            "a quoted heredoc body is data, not code"
        );
    }

    #[test]
    fn assignment_prefix_is_not_the_command_word() {
        let found = commands("FOO=1 touch /etc/x");
        assert_eq!(found, vec![vec!["touch".to_string(), "/etc/x".to_string()]]);
    }

    #[test]
    fn environment_writes_are_recovered_from_every_position() {
        let names = |input: &str| {
            environment_writes(input)
                .into_iter()
                .map(|write| (write.name, write.value))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names("FOO='a b' touch x"),
            vec![("FOO".to_string(), Some("a b".to_string()))]
        );
        assert_eq!(
            names("FOO=1; ls"),
            vec![("FOO".to_string(), Some("1".to_string()))]
        );
        assert_eq!(
            names("export FOO=$X; declare -x BAR; ls"),
            vec![("FOO".to_string(), None), ("BAR".to_string(), None)]
        );
        assert_eq!(names(": ${FOO:=x}"), vec![("FOO".to_string(), None)]);
        assert_eq!(names("FOO+=x ls"), vec![("FOO".to_string(), None)]);
        assert!(names("echo ${FOO:-x} FOO=1").is_empty());
    }

    #[test]
    fn pr170_quoted_declaration_arguments_are_environment_writes() {
        for input in [
            "export 'FOO=a b'",
            "declare -x \"FOO=a b\"",
            "export F'O'O='a b'",
        ] {
            assert_eq!(
                environment_writes(input),
                vec![EnvWrite {
                    name: "FOO".to_string(),
                    value: Some("a b".to_string()),
                }],
                "{input}"
            );
        }
        assert_eq!(
            environment_writes("export 'FOO'"),
            vec![EnvWrite {
                name: "FOO".to_string(),
                value: None,
            }]
        );
        assert_eq!(
            environment_writes(r#"export "FOO=$BAR""#),
            vec![EnvWrite {
                name: "FOO".to_string(),
                value: None,
            }]
        );
        assert!(environment_writes("echo 'FOO=a b'").is_empty());
    }

    #[test]
    fn static_command_words_are_normalized_like_bash() {
        for (input, expected) in [
            (r#""git" push"#, "git"),
            ("'git' push", "git"),
            (r#"g""it push"#, "git"),
            (r#"g\it push"#, "git"),
            (r#"/usr/bin/"git" push"#, "/usr/bin/git"),
            ("$'g\\x69t' push", "git"),
        ] {
            assert_eq!(commands(input)[0][0], expected, "input: {input}");
        }
    }

    #[test]
    fn dynamic_command_words_retain_their_source_spelling() {
        for input in [r#""$COMMAND" push"#, r#"${COMMAND} push"#, r#"$"git" push"#] {
            assert_eq!(commands(input)[0][0], input.trim_end_matches(" push"));
        }
    }

    #[test]
    fn invalid_syntax_fails_closed() {
        match parse_shell("this is ( not valid bash") {
            ShellParse::TooComplex(reason) => assert!(reason.contains("not valid syntax")),
            other => panic!("invalid syntax must not be understood, got {other:?}"),
        }
    }

    /// Anti-drift lock. Every node kind the linked grammar can emit must be
    /// classified — understood, explicitly rejected, or anonymous. A grammar
    /// upgrade that adds a kind fails here instead of silently reaching the
    /// walker's fail-closed branch.
    #[test]
    fn grammar_kinds_are_all_classified() {
        let language: tree_sitter::Language = tree_sitter_bash::LANGUAGE.into();
        let mut unclassified = Vec::new();

        for id in 0..language.node_kind_count() {
            let id = id as u16;
            let Some(kind) = language.node_kind_for_id(id) else {
                continue;
            };
            if !language.node_kind_is_named(id) || !language.node_kind_is_visible(id) {
                continue;
            }
            // `ERROR` is handled structurally by `Node::is_error`.
            if kind == "ERROR" {
                continue;
            }
            let known = STRUCTURAL_KINDS.contains(&kind)
                || REJECTED_KINDS.iter().any(|(name, _)| *name == kind);
            if !known {
                unclassified.push(kind);
            }
        }

        unclassified.sort_unstable();
        unclassified.dedup();
        assert!(
            unclassified.is_empty(),
            "the bash grammar can emit {} node kind(s) this module does not classify. \
             Each currently fails closed, which is safe but untested — decide \
             deliberately whether the walker should understand or reject it, then add \
             it to STRUCTURAL_KINDS or REJECTED_KINDS:\n  {}",
            unclassified.len(),
            unclassified.join("\n  ")
        );
    }
}
