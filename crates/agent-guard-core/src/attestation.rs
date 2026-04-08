use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::SystemTime;

/// Represents a cryptographically signed proof of a tool execution.
/// Part of Phase 8: Remote Attestation & Provenance.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExecutionProof {
    pub version: u8,
    pub timestamp: u64,
    pub payload_hash: String,
    pub sandbox_type: String,
    pub exit_code: i32,
    pub host_measurement: Option<String>, // Placeholder for TPM PCR values
    pub signature: String,
}

impl ExecutionProof {
    pub fn create(
        signing_key: &SigningKey,
        payload: &str,
        sandbox_type: &str,
        exit_code: i32,
        host_measurement: Option<String>,
    ) -> Self {
        let version = 1;
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        let payload_hash = hex::encode(hasher.finalize());

        // Prepare data for signing
        let data_to_sign = format!(
            "{}:{}:{}:{}:{}",
            version, timestamp, payload_hash, sandbox_type, exit_code
        );

        let signature = signing_key.sign(data_to_sign.as_bytes());

        Self {
            version,
            timestamp,
            payload_hash,
            sandbox_type: sandbox_type.to_string(),
            exit_code,
            host_measurement,
            signature: hex::encode(signature.to_bytes()),
        }
    }

    pub fn verify(&self, verifying_key: &VerifyingKey) -> bool {
        let data_to_sign = format!(
            "{}:{}:{}:{}:{}",
            self.version, self.timestamp, self.payload_hash, self.sandbox_type, self.exit_code
        );

        if let Ok(sig_bytes) = hex::decode(&self.signature) {
            if let Ok(sig) = Signature::from_slice(&sig_bytes) {
                return verifying_key.verify(data_to_sign.as_bytes(), &sig).is_ok();
            }
        }
        false
    }
}
