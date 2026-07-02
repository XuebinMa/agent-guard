use agent_guard_core::GuardDecision;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Version of the receipt schema.
pub const RECEIPT_VERSION: &str = "1.0";

/// Human-approval provenance attached to a receipt when the execution proceeded
/// because a human approved an `ask` (S7-5). Bound into the signed payload, so
/// it is as tamper-evident as the rest of the receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalProof {
    pub request_id: String,
    pub decided_by: Option<String>,
    /// Unix seconds when the approval was recorded.
    pub decided_at: u64,
}

/// A cryptographically signed record of a tool execution security context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub receipt_version: String,
    pub agent_id: String,
    pub tool: String,
    pub policy_version: String,
    pub sandbox_type: String,
    pub decision: String,
    pub command_hash: String,
    pub timestamp: u64,
    /// Present only when the execution was authorised by a human approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalProof>,
    /// Hex-encoded Ed25519 signature.
    pub signature: String,
}

/// Append `field` to `buf` as an 8-byte little-endian length prefix followed by
/// the field's bytes. The prefix makes a concatenation of fields injective, so
/// no two distinct field sequences can produce the same byte string.
fn push_len_prefixed(buf: &mut Vec<u8>, field: &str) {
    buf.extend_from_slice(&(field.len() as u64).to_le_bytes());
    buf.extend_from_slice(field.as_bytes());
}

impl ExecutionReceipt {
    /// Create and sign a new execution receipt.
    pub fn sign(
        agent_id: &str,
        tool: &str,
        policy_version: &str,
        sandbox_type: &str,
        decision: &GuardDecision,
        command_hash: &str,
        signing_key: &SigningKey,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_else(|_| {
                // A pre-epoch clock would silently stamp the receipt with 0,
                // weakening the execution-proof attestation. Make it observable.
                tracing::warn!(
                    "system clock is before UNIX_EPOCH; execution receipt timestamp falls back to 0"
                );
                0
            });

        let outcome = match decision {
            GuardDecision::Allow => "allow",
            GuardDecision::Deny { .. } => "deny",
            GuardDecision::AskUser { .. } => "ask",
            // Fail closed: record an unrecognized decision as a denial, never allow.
            _ => "deny",
        };

        let mut receipt = Self {
            receipt_version: RECEIPT_VERSION.to_string(),
            agent_id: agent_id.to_string(),
            tool: tool.to_string(),
            policy_version: policy_version.to_string(),
            sandbox_type: sandbox_type.to_string(),
            decision: outcome.to_string(),
            command_hash: command_hash.to_string(),
            timestamp,
            approval: None,
            signature: String::new(),
        };

        // Canonical, injective message to sign (see `to_signing_payload`).
        let message = receipt.to_signing_payload();
        let signature = signing_key.sign(&message);
        receipt.signature = hex::encode(signature.to_bytes());

        receipt
    }

    /// Attach human-approval provenance (S7-5) and re-sign so the signature
    /// covers it. Used by the approval-resume path; the direct execute path
    /// leaves `approval` as `None`.
    pub fn with_approval(mut self, approval: ApprovalProof, signing_key: &SigningKey) -> Self {
        self.approval = Some(approval);
        let message = self.to_signing_payload();
        let signature = signing_key.sign(&message);
        self.signature = hex::encode(signature.to_bytes());
        self
    }

    /// Verifies the receipt signature against a public key.
    pub fn verify(&self, public_key_bytes: &[u8; 32]) -> bool {
        use ed25519_dalek::VerifyingKey;

        let Ok(verifying_key) = VerifyingKey::from_bytes(public_key_bytes) else {
            return false;
        };

        let Ok(signature_bytes) = hex::decode(&self.signature) else {
            return false;
        };

        let Ok(signature) = Signature::from_slice(&signature_bytes) else {
            return false;
        };

        let message = self.to_signing_payload();
        verifying_key.verify(&message, &signature).is_ok()
    }

    fn to_signing_payload(&self) -> Vec<u8> {
        // Injective, length-prefixed signing payload. Each field is written as
        // its byte length (u64 LE) followed by its bytes, so an
        // attacker-influenced field (e.g. `agent_id`, sourced from the untrusted
        // Context) cannot be crafted to collide with a different field split —
        // the previous colon-join let `{agent_id:"a:b", tool:"c"}` and
        // `{agent_id:"a", tool:"b:c"}` sign to identical bytes. This is
        // panic-free by construction (no fallible serialization step in a
        // signing path). `approval` is bound with a presence byte, and its
        // `decided_by` with its own presence byte so `None` and `Some("")` do
        // not collide.
        let mut buf = Vec::new();
        for field in [
            self.receipt_version.as_str(),
            self.agent_id.as_str(),
            self.tool.as_str(),
            self.policy_version.as_str(),
            self.sandbox_type.as_str(),
            self.decision.as_str(),
            self.command_hash.as_str(),
        ] {
            push_len_prefixed(&mut buf, field);
        }
        buf.extend_from_slice(&self.timestamp.to_le_bytes());

        match &self.approval {
            None => buf.push(0),
            Some(approval) => {
                buf.push(1);
                push_len_prefixed(&mut buf, &approval.request_id);
                match &approval.decided_by {
                    None => buf.push(0),
                    Some(decided_by) => {
                        buf.push(1);
                        push_len_prefixed(&mut buf, decided_by);
                    }
                }
                buf.extend_from_slice(&approval.decided_at.to_le_bytes());
            }
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_receipt_sign_and_verify() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let public_key = signing_key.verifying_key();

        let decision = GuardDecision::Allow;
        let receipt = ExecutionReceipt::sign(
            "agent-1",
            "bash",
            "v1.0.0",
            "linux-seccomp",
            &decision,
            "hash123",
            &signing_key,
        );

        assert!(receipt.verify(&public_key.to_bytes()));
    }

    #[test]
    fn test_receipt_tamper_detection() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let public_key = signing_key.verifying_key();

        let decision = GuardDecision::Allow;
        let mut receipt = ExecutionReceipt::sign(
            "agent-1",
            "bash",
            "v1.0.0",
            "linux-seccomp",
            &decision,
            "hash123",
            &signing_key,
        );

        // Tamper with data
        receipt.decision = "deny".to_string();

        assert!(!receipt.verify(&public_key.to_bytes()));
    }

    fn approved_receipt(signing_key: &SigningKey) -> ExecutionReceipt {
        ExecutionReceipt::sign(
            "agent-1",
            "bash",
            "v1.0.0",
            "linux-seccomp",
            &GuardDecision::AskUser {
                message: "git push".to_string(),
                reason: agent_guard_core::DecisionReason::new(
                    agent_guard_core::DecisionCode::AskRequired,
                    "ask",
                ),
            },
            "hash123",
            signing_key,
        )
        .with_approval(
            ApprovalProof {
                request_id: "req-1".to_string(),
                decided_by: Some("alice".to_string()),
                decided_at: 1_700_000_000,
            },
            signing_key,
        )
    }

    #[test]
    fn approved_receipt_verifies_and_carries_provenance() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key();

        let receipt = approved_receipt(&signing_key);

        assert!(receipt.verify(&public_key.to_bytes()));
        let approval = receipt.approval.as_ref();
        assert_eq!(approval.map(|a| a.request_id.as_str()), Some("req-1"));
        assert_eq!(
            approval.and_then(|a| a.decided_by.as_deref()),
            Some("alice")
        );
    }

    #[test]
    fn tampering_approver_breaks_verification() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key();

        let mut receipt = approved_receipt(&signing_key);
        // Forge who approved it.
        if let Some(approval) = receipt.approval.as_mut() {
            approval.decided_by = Some("mallory".to_string());
        }

        assert!(!receipt.verify(&public_key.to_bytes()));
    }

    #[test]
    fn colon_in_agent_id_cannot_forge_field_boundaries() {
        // Regression for the non-injective signing payload. `agent_id` is
        // attacker-influenced and may contain ':'. Under the old colon-join,
        // {agent_id:"acme:bash", tool:"write_file"} and
        // {agent_id:"acme", tool:"bash:write_file"} produced byte-identical
        // signed messages, so one signature validated both. The JSON-tuple
        // payload binds field boundaries, so reusing r1's signature on the
        // re-split must now fail to verify.
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();

        let r1 = ExecutionReceipt::sign(
            "acme:bash",
            "write_file",
            "polv2",
            "linux-seccomp",
            &GuardDecision::Allow,
            "deadbeef",
            &signing_key,
        );
        assert!(r1.verify(&public_key));

        // Same signature, different (agent_id, tool) split.
        let mut forged = r1.clone();
        forged.agent_id = "acme".to_string();
        forged.tool = "bash:write_file".to_string();
        assert!(
            !forged.verify(&public_key),
            "re-split (agent_id, tool) must not verify under r1's signature"
        );
    }
}
