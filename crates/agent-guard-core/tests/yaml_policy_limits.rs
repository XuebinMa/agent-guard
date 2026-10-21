//! Finite, harmless inputs lock the policy parser's resource/extension limits.
//! Nothing in these fixtures is executed or resolved as a file/network include.

use agent_guard_core::{PolicyEngine, PolicyError};

const MAX_BYTES: usize = 1024 * 1024;

fn padded_policy(bytes: usize) -> String {
    let mut yaml = String::from("version: 1\n# ");
    yaml.extend(std::iter::repeat_n('x', bytes - yaml.len()));
    assert_eq!(yaml.len(), bytes);
    yaml
}

#[test]
fn a_policy_at_the_documented_byte_limit_still_loads() {
    PolicyEngine::from_yaml_str(&padded_policy(MAX_BYTES)).expect("exactly one MiB");
}

#[test]
fn string_policies_over_one_mib_are_rejected_even_if_only_comments() {
    let error = PolicyEngine::from_yaml_str(&padded_policy(MAX_BYTES + 1))
        .expect_err("the input limit applies before parsing comments");
    assert!(matches!(error, PolicyError::ParseError(_)), "{error}");
    assert!(error.to_string().contains("1048576"), "{error}");
}

#[test]
fn file_loading_obeys_the_same_byte_limit() {
    let directory = tempfile::tempdir().expect("private fixture");
    let path = directory.path().join("policy.yaml");
    std::fs::write(&path, padded_policy(MAX_BYTES)).unwrap();
    PolicyEngine::from_yaml_file(&path).expect("file at the bound");
    std::fs::write(&path, padded_policy(MAX_BYTES + 1)).unwrap();
    assert!(PolicyEngine::from_yaml_file(&path).is_err());
}

#[test]
fn application_tags_cannot_be_ignored_as_an_ordinary_policy() {
    for yaml in [
        "!policy\nversion: 1\n",
        "version: 1\naudit:\n  enabled: !custom false\n",
        "version: 1\naudit:\n  file_path: !include missing-synthetic-fixture\n",
        "version: 1\naudit:\n  file_path: !env SYNTHETIC_ONLY\n",
    ] {
        assert!(
            PolicyEngine::from_yaml_str(yaml).is_err(),
            "unsupported tag was discarded: {yaml}"
        );
    }
}

fn alias_policy(aliases: usize) -> String {
    let mut yaml = String::from("version: 1\ntools:\n  bash:\n    deny:\n      - &rule canary\n");
    for _ in 0..aliases {
        yaml.push_str("      - *rule\n");
    }
    yaml
}

#[test]
fn finite_aliases_remain_supported_but_the_count_is_bounded() {
    PolicyEngine::from_yaml_str(&alias_policy(64)).expect("supported alias count");
    assert!(
        PolicyEngine::from_yaml_str(&alias_policy(65)).is_err(),
        "alias budget must be enforced"
    );
}

#[test]
fn anchor_count_is_bounded_independently_of_aliases() {
    let mut yaml = String::from("version: 1\ntools:\n  bash:\n    deny:\n");
    for index in 0..64 {
        yaml.push_str(&format!("      - &a{index} canary\n"));
    }
    PolicyEngine::from_yaml_str(&yaml).expect("supported anchor count");
    yaml.push_str("      - &a64 canary\n");
    assert!(PolicyEngine::from_yaml_str(&yaml).is_err());
}

#[test]
fn a_large_but_small_byte_count_rule_list_hits_the_node_budget() {
    let mut yaml = String::from("version: 1\ntools:\n  bash:\n    deny:\n");
    for _ in 0..17_000 {
        yaml.push_str("      - x\n");
    }
    assert!(yaml.len() < MAX_BYTES);
    assert!(
        PolicyEngine::from_yaml_str(&yaml).is_err(),
        "node limits must not depend only on the byte cap"
    );
}

#[test]
fn deep_invalid_rule_data_is_stopped_by_a_structural_limit() {
    let yaml = format!(
        "version: 1\ntools:\n  bash:\n    deny:\n      - {}canary{}\n",
        "[".repeat(100),
        "]".repeat(100)
    );
    let error = PolicyEngine::from_yaml_str(&yaml).expect_err("invalid nested rule");
    let message = error.to_string().to_ascii_lowercase();
    assert!(
        message.contains("depth")
            || message.contains("nesting")
            || message.contains("recursion limit"),
        "{message}"
    );
}

#[test]
fn errors_do_not_add_source_line_snippets_to_existing_diagnostics() {
    let yaml = "# SYNTHETIC_UNRELATED_COMMENT\nversion: 1\ntools: {baash: {}}\n";
    let error = PolicyEngine::from_yaml_str(yaml).expect_err("unknown tool");
    assert!(!error.to_string().contains("SYNTHETIC_UNRELATED_COMMENT"));
}

#[test]
fn distinct_yaml_keys_cannot_collide_after_conversion_to_string_keys() {
    for yaml in [
        "version: 1\ntools:\n  custom:\n    42: {deny: [canary]}\n    '42': {}\n",
        "version: 1\n!!binary tools: {bash: {deny: [canary]}}\ntools: {}\n",
        "version: 1\ntools:\n  bash:\n    deny:\n      - {!!binary prefix: canary, prefix: ordinary}\n",
    ] {
        assert!(
            PolicyEngine::from_yaml_str(yaml).is_err(),
            "normalized key collision replaced a protection: {yaml}"
        );
    }
}

#[test]
fn merge_keys_and_recursive_aliases_are_not_policy_extensions() {
    for yaml in [
        "version: 1\ntools:\n  bash:\n    <<: {deny: [canary]}\n",
        "version: 1\ntools:\n  bash: &recursive\n    deny: [*recursive]\n",
    ] {
        assert!(PolicyEngine::from_yaml_str(yaml).is_err(), "{yaml}");
    }
}

fn replay_policy(copies: usize) -> String {
    let mut yaml =
        String::from("version: 1\ntools:\n  custom:\n    original: &rules\n      deny:\n");
    for _ in 0..256 {
        yaml.push_str("        - canary\n");
    }
    for index in 0..copies {
        yaml.push_str(&format!("    copy{index}: *rules\n"));
    }
    yaml
}

#[test]
fn replay_work_is_bounded_below_the_alias_count_limit() {
    PolicyEngine::from_yaml_str(&replay_policy(2)).expect("small finite replay");
    let yaml = replay_policy(40);
    assert!(yaml.len() < MAX_BYTES);
    let error = PolicyEngine::from_yaml_str(&yaml).expect_err("bounded replay work");
    assert!(
        error.to_string().to_lowercase().contains("replay"),
        "{error}"
    );
}
