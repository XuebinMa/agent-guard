use agent_guard_core::GuardDecision;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Version of the receipt schema.
pub const RECEIPT_VERSION: &str = "1.0";

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
            signature: String::new(),
        };

        // Canonical message to sign: concatenating key fields
        let message = receipt.to_signing_payload();
        let signature = signing_key.sign(message.as_bytes());
        receipt.signature = hex::encode(signature.to_bytes());

        receipt
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
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            self.receipt_version,
            self.agent_id,
            self.tool,
            self.policy_version,
            self.sandbox_type,
            self.decision,
            self.command_hash,
            self.timestamp
        )
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
}
