//! Decision-only regression locks for the bounded shell front-end.
//! These strings are parsed and classified; none is executed by a shell.

use agent_guard_validators::bash::{
    canonical_policy_subjects, validate_bash_command, PermissionMode, ValidationResult,
};
use std::path::Path;

#[test]
fn unquoted_control_bytes_cannot_create_a_grammar_only_comment() {
    for byte in ['\u{0b}', '\u{0c}', '\r'] {
        let input = format!("ls {byte}#;printf visible");
        assert!(canonical_policy_subjects(&input).is_err(), "{input:?}");
    }
}

#[test]
fn nested_executable_regions_do_not_inherit_outer_literal_exemptions() {
    for byte in ['\u{0b}', '\u{0c}', '\r'] {
        for input in [
            format!("echo \"$(ls {byte}#;printf visible\n)\""),
            format!("echo \"`ls {byte}#;printf visible\n`\""),
            format!("cat <<EOF\n$(ls {byte}#;printf visible\n)\nEOF"),
        ] {
            assert!(canonical_policy_subjects(&input).is_err(), "{input:?}");
        }
    }
}

#[test]
fn computed_command_words_are_not_empty_environment_assignments() {
    for input in [
        "=printf visible",
        "nice =printf visible",
        "env =printf visible",
    ] {
        assert!(
            matches!(
                validate_bash_command(
                    input,
                    PermissionMode::WorkspaceWrite,
                    Path::new("/workspace"),
                    &[],
                ),
                ValidationResult::Block { .. }
            ),
            "{input:?}",
        );
    }
}

#[test]
fn literal_assignment_looking_command_words_are_never_discarded() {
    for input in [
        "\"NAME=value\" echo safe",
        "N'A'ME=value echo safe",
        "nice NAME=value echo safe",
        "timeout 1 NAME=value echo safe",
        "command NAME=value echo safe",
    ] {
        assert_ne!(
            validate_bash_command(
                input,
                PermissionMode::ReadOnly,
                Path::new("/workspace"),
                &[],
            ),
            ValidationResult::Allow,
            "{input:?}",
        );
        assert!(
            !canonical_policy_subjects(input)
                .expect("static words parse")
                .iter()
                .any(|subject| subject == "echo safe"),
            "a literal executable must not become an environment prefix: {input:?}",
        );
    }
}

#[test]
fn literal_data_real_assignments_and_supported_wrappers_remain_allowed() {
    for input in [
        "echo 'a\rb'",
        "printf '%s' \"x\u{0b}y\"",
        "echo a\necho b",
        "ls\t-la",
        "echo a=b",
        "NAME=value echo safe",
        "env NAME=value echo safe",
        "env -- NAME=value echo safe",
        "nice env NAME=value echo safe",
        "NAME=value nice echo safe",
        "! NAME=value echo safe",
        "cat <<'EOF'\nline\r\nEOF",
        "cat <<EOF\nline\r\nEOF",
        "echo \"$(printf 'x\ry')\"",
        "echo safe # literal\rcomment",
    ] {
        assert!(canonical_policy_subjects(input).is_ok(), "{input:?}");
    }
    for input in [
        "NAME=value echo safe",
        "env NAME=value echo safe",
        "env -- NAME=value echo safe",
        "nice env NAME=value echo safe",
        "NAME=value nice echo safe",
        "! NAME=value echo safe",
    ] {
        assert_eq!(
            validate_bash_command(
                input,
                PermissionMode::ReadOnly,
                Path::new("/workspace"),
                &[],
            ),
            ValidationResult::Allow,
            "{input:?}",
        );
    }
}
