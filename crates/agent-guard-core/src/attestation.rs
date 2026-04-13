use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

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
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);

        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        let payload_hash = hex::encode(hasher.finalize());

        let data_to_sign = signing_payload(
            version,
            timestamp,
            &payload_hash,
            sandbox_type,
            exit_code,
            host_measurement.as_deref(),
        );
        let signature = signing_key.sign(&data_to_sign);

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
        let data_to_sign = signing_payload(
            self.version,
            self.timestamp,
            &self.payload_hash,
            &self.sandbox_type,
            self.exit_code,
            self.host_measurement.as_deref(),
        );

        if let Ok(sig_bytes) = hex::decode(&self.signature) {
            if let Ok(sig) = Signature::from_slice(&sig_bytes) {
                return verifying_key.verify(&data_to_sign, &sig).is_ok();
            }
        }
        false
    }
}

fn signing_payload(
    version: u8,
    timestamp: u64,
    payload_hash: &str,
    sandbox_type: &str,
    exit_code: i32,
    host_measurement: Option<&str>,
) -> Vec<u8> {
    serde_json::to_vec(&(
        version,
        timestamp,
        payload_hash,
        sandbox_type,
        exit_code,
        host_measurement.unwrap_or(""),
    ))
    .expect("execution proof signing payload should always serialize")
}

#[cfg(test)]
mod tests {
    use super::ExecutionProof;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn proof_verification_fails_if_host_measurement_is_tampered() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let mut proof = ExecutionProof::create(
            &signing_key,
            "echo hello",
            "linux-seccomp",
            0,
            Some("pcr0:abc123".to_string()),
        );

        assert!(proof.verify(&verifying_key));

        proof.host_measurement = Some("pcr0:tampered".to_string());
        assert!(!proof.verify(&verifying_key));
    }
}
