//! Second-issuer recompute spike for x402 PR #2666 (settlement-receipt binding).
//!
//! agent-guard issues SEP-2828 receipts over the *committed* x402 settlement
//! records (vaaraio/vaara v1.1.1 vectors), signed with agent-guard's OWN ES256
//! key, so the pinned `_check_independent.py` reproduces every verdict against a
//! second, independent issuer codebase. This turns the §7 producer-agnostic
//! property from "shown with one issuer" into "demonstrated across two".
//!
//! Scope boundary: passing the checker proves the receipt SHAPE is
//! producer-agnostic (ES256 over JCS of the five blocks + evidenceRef digest +
//! action_ref recompute). It does NOT prove end-to-end attestation-instance
//! binding — the checker never resolves `backLink` to a real ExecutionProof, so
//! `backLink` / `issuerAsserted` here are issuer-populated, not bound to a live
//! agent-guard attestation. That deeper Check-A binding stays out of this spike.

use std::fs;
use std::path::Path;

use agent_guard_core::GuardDecision;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::{EncodePublicKey, LineEnding};
use rand_core::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const RAILS: [&str; 2] = ["generic", "sui"];
const STEPS: [&str; 2] = ["step0", "step1"];

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// RFC 8785 (JCS) canonical bytes — byte-identical to the checker's
/// `rfc8785.dumps`, which is what makes the digests recompute.
fn jcs(value: &Value) -> Vec<u8> {
    serde_jcs::to_vec(value).expect("JCS canonicalization")
}

/// agent-guard's decision vocabulary mapped onto SEP-2828 `decisionDerived.decision`.
/// This is the seam that makes agent-guard the *issuer*, not a hand-rolled record.
fn decision_word(decision: &GuardDecision) -> &'static str {
    match decision {
        GuardDecision::Allow => "allow",
        GuardDecision::Deny { .. } => "deny",
        GuardDecision::AskUser { .. } => "escalate",
        // GuardDecision is #[non_exhaustive]; fail closed on anything new.
        _ => "deny",
    }
}

/// Build a SEP-2828 receipt that binds the given settlement record.
fn build_receipt(settlement: &Value, signing_key: &SigningKey) -> Value {
    let action_ref = settlement["actionRef"]
        .as_str()
        .expect("settlement.actionRef");
    let schema = settlement["schema"].as_str().expect("settlement.schema");
    let agent_id = settlement["agentId"].as_str().expect("settlement.agentId");
    let settlement_digest = sha256_hex(&jcs(settlement));

    // agent-guard is the issuer: the verdict originates from a GuardDecision.
    let decision = GuardDecision::Allow;

    // The five signed blocks. The checker signs over exactly these
    // (_DECISION_BLOCKS), with `signature` excluded; JCS re-sorts keys, so the
    // object order here is irrelevant.
    let blocks = json!({
        "version": 1,
        "alg": "ES256",
        "backLink": {
            "attestationDigest": sha256_hex(action_ref.as_bytes()),
            "attestationNonce": format!("agent-guard:{action_ref}")
        },
        "decisionDerived": {
            "decidedAt": "2026-06-23T16:40:00Z",
            "decision": decision_word(&decision),
            "evidenceRef": {
                "canonicalization": "JCS",
                "digest": settlement_digest,
                "ref": format!("x402:action_ref/{action_ref}"),
                "schema": schema
            },
            "policyId": "policy:x402-fulfillment/1",
            "reason": "agent acted within the authorized, gated scope of the settled order",
            "riskScore": "0.10",
            "thresholdAllow": "0.30",
            "thresholdBlock": "0.80"
        },
        "issuerAsserted": {
            "alg": "ES256",
            "iat": "2026-06-23T16:40:00Z",
            "iss": "issuer://agent-guard",
            "nonce": format!("ag-{action_ref}"),
            "secretVersion": "v1",
            "sub": agent_id
        }
    });

    // ES256 = ECDSA P-256 over SHA-256 of the JCS payload; raw R||S (64 bytes).
    let payload = jcs(&blocks);
    let signature: Signature = signing_key.sign(&payload);

    let mut receipt = blocks;
    receipt["signature"] = Value::String(hex::encode(signature.to_bytes()));
    receipt
}

fn main() {
    let vectors = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors");

    // One agent-guard issuer key for all receipts.
    let signing_key = SigningKey::random(&mut OsRng);
    let public_pem = signing_key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("encode ES256 public key");
    fs::write(vectors.join("keys").join("es256_public.pem"), public_pem).expect("write public key");

    for rail in RAILS {
        for step in STEPS {
            let dir = vectors.join(rail).join(step);
            let raw = fs::read(dir.join("settlement.json")).expect("read settlement.json");
            let settlement: Value = serde_json::from_slice(&raw).expect("parse settlement.json");
            let receipt = build_receipt(&settlement, &signing_key);
            let out = serde_json::to_vec_pretty(&receipt).expect("serialize receipt");
            fs::write(dir.join("receipt.json"), out).expect("write receipt.json");
            println!("issued {rail}/{step}/receipt.json");
        }
    }
    println!("agent-guard ES256 public key -> vectors/keys/es256_public.pem");
}
