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
fn argv_of(node: Node, src: &str) -> Vec<String> {
    let mut argv = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if !child.is_named() {
            continue;
        }
        match child.kind() {
            // Redirections name files, not arguments; the path gate reads
            // them separately.
            "file_redirect" | "heredoc_redirect" => continue,
            // `FOO=bar cmd` — the assignment is a prefix, not the command.
            "variable_assignment" => continue,
            _ => {}
        }
        if let Ok(text) = child.utf8_text(src.as_bytes()) {
            argv.push(word_value(child.kind(), text));
        }
    }
    argv
}

/// The value of a word, with the shell's outer quoting removed.
///
/// `argv` must carry word *values*, not source spans: the tables and wrapper
/// grammars downstream compare against unquoted words, and a re-parsed payload
/// (`watch 'echo ok; rm /etc/passwd'`) is a command list, not a string
/// literal. Expansions inside the quotes are deliberately preserved, so
/// `"$CMD"` still reads as a dynamic command word.
fn word_value(kind: &str, text: &str) -> String {
    let unquoted = match kind {
        "string" => text
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"')),
        "raw_string" => text
            .strip_prefix('\'')
            .and_then(|rest| rest.strip_suffix('\'')),
        "ansi_c_string" => text
            .strip_prefix("$'")
            .and_then(|rest| rest.strip_suffix('\'')),
        "translated_string" => text
            .strip_prefix("$\"")
            .and_then(|rest| rest.strip_suffix('"')),
        _ => None,
    };
    unquoted.unwrap_or(text).to_string()
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
