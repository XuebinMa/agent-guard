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
            .unwrap_or(0);

        let outcome = match decision {
            GuardDecision::Allow => "allow",
            GuardDecision::Deny { .. } => "deny",
            GuardDecision::AskUser { .. } => "ask",
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

        // Canonical message to sign: concatenating key fields
        let message = receipt.to_signing_payload();
        let signature = signing_key.sign(message.as_bytes());
        receipt.signature = hex::encode(signature.to_bytes());

        receipt
    }

    /// Attach human-approval provenance (S7-5) and re-sign so the signature
    /// covers it. Used by the approval-resume path; the direct execute path
    /// leaves `approval` as `None`.
    pub fn with_approval(mut self, approval: ApprovalProof, signing_key: &SigningKey) -> Self {
        self.approval = Some(approval);
        let message = self.to_signing_payload();
        let signature = signing_key.sign(message.as_bytes());
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
        verifying_key.verify(message.as_bytes(), &signature).is_ok()
    }

    fn to_signing_payload(&self) -> String {
        let base = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            self.receipt_version,
            self.agent_id,
            self.tool,
            self.policy_version,
            self.sandbox_type,
            self.decision,
            self.command_hash,
            self.timestamp
        );
        // Append approval fields only when present, so receipts without an
        // approval sign and verify exactly as before this field existed.
        match &self.approval {
            None => base,
            Some(approval) => format!(
                "{base}:approved:{}:{}:{}",
                approval.request_id,
                approval.decided_by.as_deref().unwrap_or(""),
                approval.decided_at
            ),
        }
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
    fn receipt_without_approval_signs_identically_to_before() {
        // A receipt with no approval must produce the same signing payload as
        // the pre-S7-5 format, so existing receipts still verify.
        let signing_key = SigningKey::generate(&mut OsRng);
        let receipt = ExecutionReceipt::sign(
            "agent-1",
            "bash",
            "v1.0.0",
            "linux-seccomp",
            &GuardDecision::Allow,
            "hash123",
            &signing_key,
        );

        assert!(receipt.approval.is_none());
        assert_eq!(
            receipt.to_signing_payload(),
            "1.0:agent-1:bash:v1.0.0:linux-seccomp:allow:hash123:".to_string()
                + &receipt.timestamp.to_string()
        );
    }
}
