//! Parser migration locks at the public Guard construction and reload boundary.
//!
//! All command strings are decision inputs only. These tests never execute a
//! shell, and all signing material is a fixed synthetic fixture.

use agent_guard_sdk::{
    sign_policy, Context, DecisionCode, Guard, GuardDecision, PolicyVerificationStatus, Tool,
};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

const POLICY: &str = "version: 1\ndefault_mode: full_access\ntools:\n  bash:\n    deny:\n      - prefix: \"blocked-by-policy\"\naudit:\n  enabled: false\nanomaly:\n  enabled: false\n";

fn invalid_policy_documents() -> Vec<(&'static str, String)> {
    vec![
        (
            "duplicate top-level field",
            format!("{POLICY}default_mode: read_only\n"),
        ),
        (
            "duplicate rule mapping field",
            POLICY.replace(
                "prefix: \"blocked-by-policy\"",
                "prefix: \"blocked-by-policy\"\n        prefix: \"different\"",
            ),
        ),
        (
            "second YAML document",
            format!("{POLICY}---\nversion: 1\ndefault_mode: full_access\n"),
        ),
        (
            "boolean rule",
            POLICY.replace("prefix: \"blocked-by-policy\"", "true"),
        ),
        (
            "numeric rule",
            POLICY.replace("prefix: \"blocked-by-policy\"", "17"),
        ),
        (
            "sequence rule",
            POLICY.replace("prefix: \"blocked-by-policy\"", "[]"),
        ),
        (
            "null rule",
            POLICY.replace("prefix: \"blocked-by-policy\"", "null"),
        ),
        (
            "non-string prefix",
            POLICY.replace("prefix: \"blocked-by-policy\"", "prefix: 17"),
        ),
    ]
}

fn decision(guard: &Guard, command: &str) -> GuardDecision {
    let payload = serde_json::json!({ "command": command }).to_string();
    guard.check_tool(Tool::Bash, &payload, Context::default())
}

fn assert_denied(guard: &Guard, command: &str, code: DecisionCode) {
    match decision(guard, command) {
        GuardDecision::Deny { reason } => assert_eq!(reason.code(), code),
        other => panic!("expected {code:?} for {command:?}, got {other:?}"),
    }
}

fn assert_original_policy(guard: &Guard, original_hash: &str) {
    assert_eq!(guard.policy_hash(), original_hash);
    assert_eq!(guard.policy_version(), original_hash);
    assert_denied(guard, "blocked-by-policy", DecisionCode::DeniedByRule);
    assert_eq!(decision(guard, "echo harmless"), GuardDecision::Allow);
}

fn raw_hash(yaml: &str) -> String {
    hex::encode(Sha256::digest(yaml.as_bytes()))
}

fn signing_fixture() -> (SigningKey, String, String) {
    let key = SigningKey::from_bytes(&[0x39; 32]);
    let public_key = hex::encode(key.verifying_key().to_bytes());
    let signature = sign_policy(POLICY, &key);
    (key, public_key, signature)
}

#[test]
fn guard_constructor_rejects_ambiguous_or_non_string_policy_rules() {
    Guard::from_yaml(POLICY).expect("valid control policy");
    for (case, yaml) in invalid_policy_documents() {
        assert!(
            Guard::from_yaml(&yaml).is_err(),
            "Guard unexpectedly accepted {case}"
        );
    }
}

#[test]
fn guard_file_constructor_uses_the_same_policy_validation() {
    let directory = tempfile::tempdir().expect("fixture directory");
    let path = directory.path().join("policy.yaml");
    std::fs::write(&path, POLICY).expect("write valid fixture");
    let guard = Guard::from_yaml_file(&path).expect("valid file control");
    assert_original_policy(&guard, &raw_hash(POLICY));

    for (case, yaml) in invalid_policy_documents() {
        std::fs::write(&path, yaml).expect("write invalid fixture");
        assert!(
            Guard::from_yaml_file(&path).is_err(),
            "file constructor unexpectedly accepted {case}"
        );
    }
}

#[test]
fn parse_failure_during_reload_keeps_the_previous_hash_and_deny_rule() {
    let guard = Guard::from_yaml(POLICY).expect("valid control policy");
    let original_hash = guard.policy_hash();
    assert_eq!(original_hash, raw_hash(POLICY));

    for (case, yaml) in invalid_policy_documents() {
        assert!(
            guard.reload_from_yaml(&yaml).is_err(),
            "reload unexpectedly accepted {case}"
        );
        assert_original_policy(&guard, &original_hash);
        assert_eq!(
            guard.policy_verification().status,
            PolicyVerificationStatus::Unsigned
        );
    }
}

#[test]
fn signing_invalid_yaml_does_not_make_it_a_valid_policy() {
    let (key, public_key, _) = signing_fixture();
    for (case, yaml) in invalid_policy_documents() {
        let signature = sign_policy(&yaml, &key);
        assert!(
            Guard::from_signed_yaml(&yaml, &public_key, &signature).is_err(),
            "a valid detached signature unexpectedly legitimized {case}"
        );
    }
}

#[test]
fn signed_parse_failure_during_reload_keeps_the_verified_snapshot() {
    let (key, public_key, signature) = signing_fixture();
    let guard = Guard::from_signed_yaml(POLICY, &public_key, &signature)
        .expect("valid signed control policy");
    let original_hash = guard.policy_hash();

    for (case, yaml) in invalid_policy_documents() {
        let invalid_document_signature = sign_policy(&yaml, &key);
        assert!(
            guard
                .reload_from_signed_yaml(&yaml, &public_key, &invalid_document_signature)
                .is_err(),
            "signed reload unexpectedly accepted {case}"
        );
        assert_original_policy(&guard, &original_hash);
        assert_eq!(
            guard.policy_verification().status,
            PolicyVerificationStatus::Verified
        );
    }
}

#[test]
fn policy_hash_and_signature_remain_bound_to_original_yaml_bytes() {
    let (key, public_key, signature) = signing_fixture();
    let guard = Guard::from_signed_yaml(POLICY, &public_key, &signature)
        .expect("valid signed control policy");
    assert_eq!(
        guard.policy_verification().status,
        PolicyVerificationStatus::Verified
    );
    assert_original_policy(&guard, &raw_hash(POLICY));

    for (case, changed) in [
        ("added comment", format!("# byte-binding fixture\n{POLICY}")),
        ("CRLF line endings", POLICY.replace('\n', "\r\n")),
    ] {
        // Positive controls: the same rules parse unchanged, and a signature
        // made for these exact bytes verifies. The original signature must not.
        let unsigned = Guard::from_yaml(&changed).expect("semantically equivalent YAML");
        assert_original_policy(&unsigned, &raw_hash(&changed));
        assert_ne!(unsigned.policy_hash(), guard.policy_hash(), "{case}");

        let changed_signature = sign_policy(&changed, &key);
        let resigned = Guard::from_signed_yaml(&changed, &public_key, &changed_signature)
            .expect("equivalent policy signed with its exact bytes");
        assert_eq!(
            resigned.policy_verification().status,
            PolicyVerificationStatus::Verified,
            "{case}"
        );
        assert_original_policy(&resigned, &raw_hash(&changed));

        let invalid = Guard::from_signed_yaml(&changed, &public_key, &signature)
            .expect("parseable policy constructs a fail-closed unverified Guard");
        invalid.set_audit_sink(Box::new(std::io::sink()));
        assert_eq!(
            invalid.policy_verification().status,
            PolicyVerificationStatus::Invalid,
            "the original signature must not verify after {case}"
        );
        assert_eq!(invalid.policy_hash(), raw_hash(&changed));
        assert_denied(
            &invalid,
            "echo harmless",
            DecisionCode::PolicyVerificationFailed,
        );
    }
}

#[test]
fn signed_policy_files_enforce_the_input_limit_without_replacing_the_snapshot() {
    let directory = tempfile::tempdir().expect("signed fixture directory");
    let policy_path = directory.path().join("policy.yaml");
    let public_key_path = directory.path().join("public-key.hex");
    let signature_path = directory.path().join("signature.hex");
    let (key, public_key, signature) = signing_fixture();
    std::fs::write(&policy_path, POLICY).expect("write signed control policy");
    std::fs::write(&public_key_path, public_key).expect("write public fixture key");
    std::fs::write(&signature_path, signature).expect("write fixture signature");

    let guard = Guard::from_signed_yaml_file(&policy_path, &public_key_path, &signature_path)
        .expect("exact-byte signed policy file loads");
    let original_hash = raw_hash(POLICY);
    assert_original_policy(&guard, &original_hash);
    assert_eq!(
        guard.policy_verification().status,
        PolicyVerificationStatus::Verified
    );

    // A synthetic comment takes an otherwise valid policy over one MiB.
    // Sign those exact bytes so the size check, not a bad signature, rejects it.
    // Do not include this large document in assertion messages or error output.
    let oversized = format!("{POLICY}# {}\n", "x".repeat(1024 * 1024));
    std::fs::write(&policy_path, &oversized).expect("write oversized policy fixture");
    std::fs::write(&signature_path, sign_policy(&oversized, &key))
        .expect("write oversized fixture signature");
    assert!(
        Guard::from_signed_yaml_file(&policy_path, &public_key_path, &signature_path).is_err(),
        "a signed policy file over one MiB must not construct a Guard"
    );
    assert!(
        guard
            .reload_from_signed_yaml_file(&policy_path, &public_key_path, &signature_path)
            .is_err(),
        "a signed policy file over one MiB must not replace the active snapshot"
    );
    assert_original_policy(&guard, &original_hash);
    assert_eq!(
        guard.policy_verification().status,
        PolicyVerificationStatus::Verified
    );

    let restored = format!("# restored fixture\r\n{}", POLICY.replace('\n', "\r\n"));
    std::fs::write(&policy_path, &restored).expect("restore a bounded policy file");
    std::fs::write(&signature_path, sign_policy(&restored, &key))
        .expect("write restored fixture signature");
    guard
        .reload_from_signed_yaml_file(&policy_path, &public_key_path, &signature_path)
        .expect("a later bounded, correctly signed policy reloads normally");
    assert_ne!(guard.policy_hash(), original_hash);
    assert_original_policy(&guard, &raw_hash(&restored));
    assert_eq!(
        guard.policy_verification().status,
        PolicyVerificationStatus::Verified
    );
}
