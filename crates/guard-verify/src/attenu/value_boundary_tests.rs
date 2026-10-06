//! Locally sealed fixtures isolate semantic validation from signature validity.
use super::test_support::{published, reseal};
use super::*;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;

#[test]
fn attenuation_preserves_the_constraint_field_scope_and_type() {
    for (parent, narrower, selector) in [
        (
            json!({"key":"bound","type":"allow","field":"destination","one_of":["A","B"]}),
            json!({"key":"bound","type":"allow","field":"destination","one_of":["A"]}),
            "field",
        ),
        (
            json!({"key":"bound","type":"deny","field":"destination","not_one_of":["A"]}),
            json!({"key":"bound","type":"deny","field":"destination","not_one_of":["A","B"]}),
            "field",
        ),
        (
            json!({"key":"bound","type":"prefix","field":"destination","prefix":"/workspace/"}),
            json!({"key":"bound","type":"prefix","field":"destination","prefix":"/workspace/sub/"}),
            "field",
        ),
        (
            json!({"key":"bound","type":"max_calls","applies_to":"crm.read","max":10}),
            json!({"key":"bound","type":"max_calls","applies_to":"crm.read","max":5}),
            "applies_to",
        ),
    ] {
        for change in 0..3 {
            let (mut bundle, signer) = published("valid_bundle_v2_literal");
            let mut child = narrower.clone();
            if change == 1 {
                child[selector] = json!(if selector == "field" {
                    "memo"
                } else {
                    "mail.send"
                });
            }
            if change == 2 {
                child.as_object_mut().unwrap().remove(selector);
            }
            bundle["entries"][0]["authority"]["constraints"] = json!([parent.clone()]);
            bundle["entries"][1]["granted"]["constraints"] = json!([child]);
            reseal(&mut bundle, &signer);
            let report = verify_bundle(&bundle, &signer);
            assert_eq!(
                report.accepted,
                change == 0,
                "{selector}, change {change}: {:?}",
                report.failures
            );
        }
    }
    let (mut bundle, signer) = published("valid_bundle_v2_literal");
    bundle["entries"][0]["authority"]["constraints"] =
        json!([{"key":"bound","type":"max_calls","applies_to":"crm.read","max":10}]);
    bundle["entries"][1]["granted"]["constraints"] = json!([{"key":"bound","max":5}]);
    reseal(&mut bundle, &signer);
    assert!(
        !verify_bundle(&bundle, &signer).accepted,
        "a typed ceiling cannot turn into an unrelated generic maximum"
    );
}

fn signed_observation(observed: Option<Value>) -> BundleReport {
    let file: super::corpus::EnvelopeVectorFile = serde_json::from_str(include_str!(
        "../../fixtures/attenu/envelope_vectors_v1.json"
    ))
    .unwrap();
    let mut case = file
        .cases
        .into_iter()
        .find(|case| case.name == "valid_spawn_envelope")
        .unwrap();
    // Synthetic unit-test key, never a production signing credential.
    let key = SigningKey::from_bytes(&[7; 32]);
    let trust = TrustSet::build(&[WitnessKey {
        kid: "local-fixture".into(),
        alg: "EdDSA".into(),
        public_key_hex: hex::encode(key.verifying_key().as_bytes()),
    }])
    .unwrap();
    let envelope = &mut case.bundle["envelopes"][0];
    envelope["witness"]["kid"] = json!("local-fixture");
    match observed {
        Some(value) => envelope["observed"] = value,
        None => {
            envelope.as_object_mut().unwrap().remove("observed");
        }
    }
    envelope.as_object_mut().unwrap().remove("sig");
    let signature = key.sign(&crate::jcs::canonicalize(envelope).unwrap());
    envelope["sig"] = json!(hex::encode(signature.to_bytes()));
    verify_bundle_with_envelopes(&case.bundle, case.signer.as_ref(), &trust, &HashMap::new())
}

#[test]
fn valid_signatures_cannot_validate_malformed_observations() {
    for observed in [
        None,
        Some(json!(7)),
        Some(json!({})),
        Some(json!({"result":"approved"})),
        Some(json!({"result":false})),
        Some(json!({"result":"matched","at":12})),
        Some(json!({"result":"matched","method":[]})),
    ] {
        let report = signed_observation(observed);
        assert!(!report.accepted);
        assert!(report
            .failures
            .iter()
            .any(|f| f.reason == "envelope_invalid_observation"));
        assert_eq!(
            report.envelopes.unwrap().states[1].state(),
            "process-asserted"
        );
    }
    for result in ["matched", "not_matched", "indeterminate"] {
        let report = signed_observation(Some(
            json!({"result":result,"at":"2026-10-04T00:00:00Z","method":"local fixture"}),
        ));
        assert!(report.accepted, "{:?}", report.failures);
        assert_eq!(
            report.envelopes.unwrap().states[1].state(),
            "witness-signed"
        );
    }
}
