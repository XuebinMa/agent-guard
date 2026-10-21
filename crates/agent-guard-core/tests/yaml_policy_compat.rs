//! Parser migration contract. Command-shaped strings are decision inputs only;
//! this suite never executes them.

use agent_guard_core::{
    Context, CustomToolId, GuardDecision, PolicyEngine, PolicyError, Tool, TrustLevel,
};
use sha2::{Digest, Sha256};

fn context() -> Context {
    Context {
        trust_level: TrustLevel::Trusted,
        ..Context::default()
    }
}

fn bash(engine: &PolicyEngine, command: &str) -> GuardDecision {
    engine.check(
        &Tool::Bash,
        &serde_json::json!({ "command": command }).to_string(),
        &context(),
    )
}

fn rejects(yaml: &str) {
    assert!(
        PolicyEngine::from_yaml_str(yaml).is_err(),
        "invalid policy unexpectedly loaded:\n{yaml}"
    );
}

#[test]
fn every_shipped_policy_loads_without_rewriting_its_source() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for relative in [
        "policy.example.yaml",
        "presets/coding-agent-outbound.yaml",
        "packages/agent-guard-plugin/assets/coding-agent-outbound.yaml",
        "crates/agent-guard-node/examples/attack-demo/policy.yaml",
        "crates/agent-guard-node/examples/chatgpt-actions/policy.yaml",
        "crates/agent-guard-node/examples/quickstart/policy.yaml",
        "tests/cross-language-parity/fixtures/policy.yaml",
    ] {
        let yaml = std::fs::read_to_string(root.join(relative)).expect("shipped policy exists");
        let engine = PolicyEngine::from_yaml_str(&yaml)
            .unwrap_or_else(|error| panic!("{relative}: {error}"));
        assert_eq!(engine.hash(), hex::encode(Sha256::digest(yaml.as_bytes())));
    }
}

#[test]
fn mixed_plain_and_map_rules_preserve_deny_ask_allow_decisions() {
    let engine = PolicyEngine::from_yaml_str(
        r#"
version: 1
default_mode: full_access
tools:
  bash:
    deny: [blocked-text, {prefix: forbidden}]
    ask: [{prefix: review}]
    allow: [{plain: safe}]
"#,
    )
    .expect("mixed rules");
    for command in [
        "contains blocked-text",
        "forbidden safe",
        "review blocked-text",
    ] {
        assert!(
            matches!(bash(&engine, command), GuardDecision::Deny { .. }),
            "{command}"
        );
    }
    assert!(matches!(
        bash(&engine, "review safe"),
        GuardDecision::AskUser { .. }
    ));
    assert_eq!(bash(&engine, "safe"), GuardDecision::Allow);
    assert_eq!(bash(&engine, "ordinary"), GuardDecision::Allow);
}

#[test]
fn escaped_regex_and_condition_strings_keep_their_meaning() {
    let engine = PolicyEngine::from_yaml_str(
        r#"
version: 1
default_mode: full_access
tools:
  bash:
    deny:
      - regex: "^review\\s+item$"
        if: 'trust_level == "trusted"'
      - if: 'agent_id == "blocked-agent"'
"#,
    )
    .expect("regex and conditions");
    assert!(matches!(
        bash(&engine, "review item"),
        GuardDecision::Deny { .. }
    ));
    assert_eq!(bash(&engine, "review-item"), GuardDecision::Allow);
    let blocked = Context {
        agent_id: Some("blocked-agent".into()),
        ..context()
    };
    assert!(matches!(
        engine.check(&Tool::Bash, r#"{"command":"ordinary"}"#, &blocked),
        GuardDecision::Deny { .. }
    ));
}

#[test]
fn method_only_rules_and_valid_custom_tools_still_apply() {
    let engine = PolicyEngine::from_yaml_str(
        r#"
version: 1
default_mode: full_access
tools:
  http_request:
    deny: [{method: propfind}]
  custom:
    acme.query:
      deny: [{plain: forbidden-query}]
"#,
    )
    .expect("method and custom rule");
    assert!(matches!(
        engine.check(
            &Tool::HttpRequest,
            r#"{"method":"PROPFIND","url":"https://example.test/"}"#,
            &context()
        ),
        GuardDecision::Deny { .. }
    ));
    let tool = Tool::Custom(CustomToolId::new("acme.query").expect("valid custom id"));
    assert!(matches!(
        engine.check(&tool, "forbidden-query", &context()),
        GuardDecision::Deny { .. }
    ));
}

#[test]
fn policy_identity_hashes_original_bytes_not_a_normalized_document() {
    let variants = [
        "version: 1\n",
        "# comment\nversion: 1\n",
        "version: 1\r\n",
        "version: 1\n\n",
    ];
    let hashes: Vec<_> = variants
        .iter()
        .map(|yaml| {
            let engine = PolicyEngine::from_yaml_str(yaml).expect("equivalent policy");
            assert_eq!(engine.hash(), hex::encode(Sha256::digest(yaml.as_bytes())));
            assert_eq!(engine.hash(), engine.version());
            assert_eq!(bash(&engine, "ordinary"), GuardDecision::Allow);
            engine.hash().to_string()
        })
        .collect();
    for (index, hash) in hashes.iter().enumerate() {
        assert!(
            !hashes[..index].contains(hash),
            "distinct raw documents need distinct hashes"
        );
    }
}

#[test]
fn absent_and_explicit_empty_audit_keep_distinct_defaults() {
    let absent = PolicyEngine::from_yaml_str("version: 1\n").expect("absent audit");
    let present = PolicyEngine::from_yaml_str("version: 1\naudit: {}\n").expect("empty audit");
    assert!(!absent.audit_config().enabled);
    assert!(!absent.audit_config().include_payload_hash);
    assert!(present.audit_config().enabled);
    assert!(present.audit_config().include_payload_hash);
    assert_eq!(absent.audit_config().output, "stdout");
    assert_eq!(present.audit_config().output, "stdout");
}

#[test]
fn json_encoded_audit_paths_preserve_backslashes_quotes_and_unicode() {
    for path in [
        r"C:\Users\alice\.claude\audit.jsonl",
        "/home/a\"b/审计.jsonl",
    ] {
        let encoded = serde_json::to_string(path).expect("encode path");
        let yaml = format!("version: 1\naudit:\n  output: file\n  file_path: {encoded}\n");
        let engine = PolicyEngine::from_yaml_str(&yaml).expect("JSON string is YAML");
        assert_eq!(engine.audit_config().file_path.as_deref(), Some(path));
    }
}

#[test]
fn supported_bom_and_crlf_unicode_block_presentations_preserve_values() {
    // Keep these supported presentations separate: the old parser rejects a
    // BOM combined with some Unicode block-scalar inputs.
    let bom = "\u{feff}version: 1\n";
    let bom_engine = PolicyEngine::from_yaml_str(bom).expect("BOM policy");
    assert_eq!(
        bom_engine.hash(),
        hex::encode(Sha256::digest(bom.as_bytes()))
    );
    let yaml = "version: 1\r\ndefault_mode: full_access\r\ntools:\r\n  bash:\r\n    deny:\r\n      - plain: |-\r\n          不允许的操作\r\n";
    let engine = PolicyEngine::from_yaml_str(yaml).expect("CRLF and Unicode block policy");
    assert!(matches!(
        bash(&engine, "包含不允许的操作"),
        GuardDecision::Deny { .. }
    ));
    assert_eq!(bash(&engine, "普通操作"), GuardDecision::Allow);
    assert_eq!(engine.hash(), hex::encode(Sha256::digest(yaml.as_bytes())));
}

#[test]
fn finite_anchors_and_aliases_preserve_rule_and_mode_values() {
    let engine = PolicyEngine::from_yaml_str(
        r#"
version: 1
default_mode: &mode full_access
tools:
  bash:
    mode: *mode
    deny:
      - &rule {prefix: forbidden}
      - *rule
"#,
    )
    .expect("finite aliases");
    assert!(matches!(
        bash(&engine, "forbidden action"),
        GuardDecision::Deny { .. }
    ));
    assert_eq!(bash(&engine, "ordinary"), GuardDecision::Allow);
}

#[test]
fn quoted_scalar_lookalikes_stay_string_rules() {
    let engine = PolicyEngine::from_yaml_str("version: 1\ndefault_mode: full_access\ntools:\n  bash:\n    deny: ['42', 'true', 'null', {prefix: 'false'}]\n").expect("quoted strings");
    for command in ["42", "true", "null", "false statement"] {
        assert!(
            matches!(bash(&engine, command), GuardDecision::Deny { .. }),
            "{command}"
        );
    }
}

#[test]
fn only_yaml_1_2_boolean_spellings_are_valid_boolean_configuration() {
    for (scalar, expected) in [
        ("true", true),
        ("True", true),
        ("TRUE", true),
        ("false", false),
        ("False", false),
        ("FALSE", false),
    ] {
        let yaml = format!("version: 1\naudit:\n  enabled: {scalar}\n");
        let engine = PolicyEngine::from_yaml_str(&yaml).expect("YAML 1.2 boolean");
        assert_eq!(engine.audit_config().enabled, expected, "{scalar}");
    }
    for scalar in ["yes", "no", "on", "off", "1", "'true'"] {
        rejects(&format!("version: 1\naudit:\n  enabled: {scalar}\n"));
    }
}

#[test]
fn string_and_binary_tags_preserve_lexical_string_values_without_decoding() {
    let engine = PolicyEngine::from_yaml_str(
        "version: 1\ndefault_mode: full_access\naudit:\n  output: file\n  file_path: !!binary YXVkaXQuanNvbmw=\ntools:\n  bash:\n    deny: [!!str 42, !!binary Zm9yYmlkZGVu]\n",
    )
    .expect("standard scalar tags");
    assert_eq!(
        engine.audit_config().file_path.as_deref(),
        Some("YXVkaXQuanNvbmw=")
    );
    assert!(matches!(bash(&engine, "42"), GuardDecision::Deny { .. }));
    assert!(matches!(
        bash(&engine, "Zm9yYmlkZGVu"),
        GuardDecision::Deny { .. }
    ));
    assert_eq!(bash(&engine, "forbidden"), GuardDecision::Allow);
}

#[test]
fn non_string_rule_scalars_and_non_mapping_rule_containers_are_rejected() {
    for rule in ["42", "true", "false", "null", "~", "[]", "[value]"] {
        rejects(&format!(
            "version: 1\ntools:\n  bash:\n    deny: [{rule}]\n"
        ));
    }
}

#[test]
fn map_selectors_do_not_coerce_non_string_scalars_to_strings() {
    for selector in ["prefix", "regex", "plain", "if"] {
        for value in ["42", "true", "[]", "{}"] {
            rejects(&format!(
                "version: 1\ntools:\n  bash:\n    deny:\n      - {selector}: {value}\n"
            ));
        }
    }
    for value in ["42", "true", "[]", "{}"] {
        rejects(&format!(
            "version: 1\ntools:\n  http_request:\n    deny:\n      - method: {value}\n"
        ));
    }
}

#[test]
fn duplicate_keys_cannot_replace_an_earlier_protection() {
    for yaml in [
        "version: 1\nversion: 1\n",
        "version: 1\ndefault_mode: blocked\ndefault_mode: full_access\n",
        "version: 1\ntools: {bash: {deny: [forbidden]}}\ntools: {}\n",
        "version: 1\ntools:\n  bash: {deny: [forbidden]}\n  bash: {}\n",
        "version: 1\ntools:\n  bash:\n    deny: [forbidden]\n    deny: []\n",
        "version: 1\ntools:\n  bash:\n    deny: [{prefix: forbidden, prefix: harmless}]\n",
        "version: 1\ntools:\n  custom:\n    acme.query: {deny: [forbidden]}\n    acme.query: {}\n",
    ] {
        rejects(yaml);
    }
}

#[test]
fn unknown_fields_at_every_fixed_schema_layer_are_rejected() {
    for yaml in [
        "version: 1\ndenny: true\n",
        "version: 1\ntools: {baash: {}}\n",
        "version: 1\ntools: {bash: {denny: []}}\n",
        "version: 1\ntools: {bash: {deny: [{prefx: forbidden}]}}\n",
        "version: 1\ntrust: {trusted: {overide_mode: full_access}}\n",
        "version: 1\naudit: {enabld: false}\n",
        "version: 1\nanomaly: {enabld: false}\n",
        "version: 1\nanomaly: {rate_limit: {max_call: 1}}\n",
        "version: 1\nanomaly: {deny_fuse: {thresholdd: 1}}\n",
        "version: 1\ninput_content: {mode: block, detct: []}\n",
        "version: 1\ntools: {write_file: {content: {mode: block, detct: []}}}\n",
    ] {
        rejects(yaml);
    }
}

#[test]
fn null_optional_values_do_not_make_null_rule_lists_valid() {
    let engine = PolicyEngine::from_yaml_str(
        "version: 1\ninput_content: null\ntools:\n  bash:\n    mode: null\n    content: null\n",
    )
    .expect("optional values accept null");
    assert!(engine.content_policy(&Tool::Bash).is_none());
    for field in [
        "deny",
        "allow",
        "ask",
        "deny_paths",
        "allow_paths",
        "workspace_escape_paths",
    ] {
        rejects(&format!("version: 1\ntools:\n  bash:\n    {field}: null\n"));
    }
}

#[test]
fn trailing_documents_cannot_hide_a_second_policy() {
    for yaml in [
        "version: 1\n---\nversion: 1\ndefault_mode: full_access\n",
        "---\nversion: 1\n...\n---\nversion: 1\n",
        "version: 1\n---\n",
    ] {
        rejects(yaml);
    }
    PolicyEngine::from_yaml_str("---\nversion: 1\n...\n").expect("one explicit document");
}

#[test]
fn malformed_roots_missing_version_and_unsupported_versions_fail_at_load() {
    for yaml in [
        "",
        "42",
        "[]",
        "null",
        "default_mode: full_access\n",
        "version: [1]\n",
        "version: 1\ntools: [\n",
    ] {
        rejects(yaml);
    }
    assert!(matches!(
        PolicyEngine::from_yaml_str("version: 2\n"),
        Err(PolicyError::UnsupportedVersion(2))
    ));
}

#[test]
fn typed_condition_errors_and_invalid_patterns_remain_load_errors() {
    for rule in [
        "{prefix: forbidden, if: 'unknown_variable == \"x\"'}",
        "{if: 'trust_level > 3'}",
        "{if: actor}",
        "{regex: '['}",
        "{prefix: '   '}",
        "{}",
    ] {
        rejects(&format!(
            "version: 1\ntools:\n  bash:\n    deny: [{rule}]\n"
        ));
    }
}
