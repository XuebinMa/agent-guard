//! Explicit scalar-type contracts for the replacement YAML parser.
//!
//! String fields now require actual YAML strings rather than implicit scalar
//! coercion. Boolean case folding is accepted intentionally, but legacy YAML
//! 1.1 words and quoted strings must not become boolean configuration values.

use agent_guard_core::PolicyEngine;

fn audit_path_policy(scalar: &str) -> String {
    format!("version: 1\naudit:\n  output: file\n  file_path: {scalar}\n")
}

fn boolean_policy(scalar: &str) -> String {
    format!("version: 1\naudit:\n  enabled: {scalar}\n")
}

fn ascii_case_variants(word: &str) -> Vec<String> {
    (0..(1usize << word.len()))
        .map(|mask| {
            word.chars()
                .enumerate()
                .map(|(index, character)| {
                    if mask & (1usize << index) == 0 {
                        character
                    } else {
                        character.to_ascii_uppercase()
                    }
                })
                .collect()
        })
        .collect()
}

#[test]
fn quoted_numeric_and_boolean_lookalikes_preserve_exact_string_values() {
    for expected in [
        "42", "-7", "1.25", "0x2a", "true", "FALSE", "tRuE", "null", "~",
    ] {
        for quoted in [format!("'{expected}'"), format!("\"{expected}\"")] {
            let engine = PolicyEngine::from_yaml_str(&audit_path_policy(&quoted))
                .expect("quoted audit file path is a YAML string");
            assert_eq!(
                engine.audit_config().file_path.as_deref(),
                Some(expected),
                "string spelling must be retained for {quoted}"
            );
        }
    }
}

#[test]
fn string_fields_refuse_implicit_numeric_and_boolean_coercion() {
    for scalar in ["42", "0", "-7", "1.25", "true", "false", "tRuE", "fAlSe"] {
        assert!(
            PolicyEngine::from_yaml_str(&audit_path_policy(scalar)).is_err(),
            "an unquoted non-string must not become an audit file path: {scalar}"
        );

        let engine = PolicyEngine::from_yaml_str(&audit_path_policy(&format!("'{scalar}'")))
            .expect("quoting the same scalar is the supported remedy");
        assert_eq!(engine.audit_config().file_path.as_deref(), Some(scalar));
    }
}

#[test]
fn boolean_true_and_false_accept_every_ascii_case_combination() {
    let mut checked = 0;
    for (word, expected) in [("true", true), ("false", false)] {
        for scalar in ascii_case_variants(word) {
            let engine = PolicyEngine::from_yaml_str(&boolean_policy(&scalar))
                .expect("true and false are intentionally case-insensitive");
            assert_eq!(engine.audit_config().enabled, expected, "{scalar}");
            checked += 1;
        }
    }
    assert_eq!(checked, 48, "16 true spellings and 32 false spellings");
}

#[test]
fn boolean_fields_reject_legacy_words_numbers_and_quoted_booleans() {
    for word in ["yes", "no", "on", "off"] {
        for scalar in ascii_case_variants(word) {
            assert!(
                PolicyEngine::from_yaml_str(&boolean_policy(&scalar)).is_err(),
                "YAML 1.1 boolean words are not supported: {scalar}"
            );
        }
    }

    for scalar in [
        "1",
        "0",
        "'true'",
        "'false'",
        "\"true\"",
        "\"false\"",
        "'tRuE'",
        "'fAlSe'",
    ] {
        assert!(
            PolicyEngine::from_yaml_str(&boolean_policy(scalar)).is_err(),
            "a non-boolean scalar must not control audit.enabled: {scalar}"
        );
    }
}
