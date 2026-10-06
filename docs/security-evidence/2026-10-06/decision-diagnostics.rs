// Decision-only diagnostics. No command strings below are executed.
#[cfg(test)]
mod tests {
    use agent_guard_validators::bash::{
        canonical_policy_subjects, validate_bash_command, PermissionMode, ValidationResult,
    };
    use std::path::Path;

    #[test]
    fn unquoted_control_bytes_are_not_trusted_grammar_whitespace() {
        for byte in ['\u{0b}', '\u{0c}', '\r'] {
            let input = format!("ls {byte}#;printf visible");
            assert!(canonical_policy_subjects(&input).is_err());
        }
    }

    #[test]
    fn zsh_computed_command_is_not_an_empty_assignment() {
        assert!(matches!(
            validate_bash_command(
                "=touch /outside/marker",
                PermissionMode::WorkspaceWrite,
                Path::new("/workspace"),
                &[],
            ),
            ValidationResult::Block { .. }
        ));
    }

    #[test]
    fn quote_parent_does_not_make_nested_executable_text_literal() {
        for byte in ['\u{0b}', '\u{0c}', '\r'] {
            let input = format!("echo \"$(ls {byte}#;printf visible\n)\"");
            assert!(
                canonical_policy_subjects(&input).is_err(),
                "nested executable text must not inherit a literal-string exemption",
            );
        }
    }

    #[test]
    fn genuine_literal_data_and_normal_separators_still_parse() {
        for input in ["echo 'a\rb'", "echo a\necho b", "ls\t-la", "echo a=b"] {
            assert!(canonical_policy_subjects(input).is_ok());
        }
    }

    #[test]
    fn literal_assignment_looking_command_is_not_a_shell_assignment() {
        for input in ["\"NAME=value\" echo safe", "nice NAME=value echo safe"] {
            let result = validate_bash_command(
                input,
                PermissionMode::ReadOnly,
                Path::new("/workspace"),
                &[],
            );
            assert_ne!(result, ValidationResult::Allow, "literal command words must not be discarded");
        }
    }
}
