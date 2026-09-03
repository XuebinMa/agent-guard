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

/// A host's signed statement about an outcome it produced outside the Guard.
///
/// `RuntimeOutcome::Handoff` gives the action to the host, which executes it
/// beyond the Guard's boundary and reports back. The resulting
/// `ExecutionReported` record identifies where the claim came from; this is
/// what lets a reader re-check it.
///
/// ## What it establishes, and what it cannot
///
/// The signature binds a named key to an exact claim — this request, this
/// exit code, this duration. A third party cannot forge it, and an edit to
/// the recorded outcome stops matching it, so tampering is detectable.
///
/// It does not make the exit code true. The execution happened outside the
/// boundary and nothing signed inside the boundary can reach it: a host that
/// lies about its own result will produce a perfectly valid attestation of
/// that lie. What changes is that the lie becomes attributable to a named key
/// and cannot be quietly revised afterwards, and that a reader can tell an
/// attested claim from an unattested one instead of having to treat both the
/// same way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostAttestation {
    pub version: u8,
    /// Names the key that signed, so a verifier knows which one to check
    /// against. It is the host's own label and is not itself authenticated.
    pub key_id: String,
    /// The claim is restated here rather than referenced, so the signature
    /// covers the values themselves instead of whatever the surrounding
    /// record happens to say later.
    pub request_id: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub signature: String,
}

impl HostAttestation {
    pub fn create(
        signing_key: &SigningKey,
        key_id: &str,
        request_id: &str,
        exit_code: i32,
        duration_ms: u64,
    ) -> Self {
        let version = 1;
        let data_to_sign =
            host_attestation_payload(version, key_id, request_id, exit_code, duration_ms);
        let signature = signing_key.sign(&data_to_sign);

        Self {
            version,
            key_id: key_id.to_string(),
            request_id: request_id.to_string(),
            exit_code,
            duration_ms,
            signature: hex::encode(signature.to_bytes()),
        }
    }

    /// Check the signature against a host key the verifier already trusts.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> bool {
        let data_to_sign = host_attestation_payload(
            self.version,
            &self.key_id,
            &self.request_id,
            self.exit_code,
            self.duration_ms,
        );

        if let Ok(sig_bytes) = hex::decode(&self.signature) {
            if let Ok(sig) = Signature::from_slice(&sig_bytes) {
                return verifying_key.verify(&data_to_sign, &sig).is_ok();
            }
        }
        false
    }

    /// Whether this attestation is about the outcome described.
    ///
    /// Checkable without any key, which is what lets the Guard refuse to
    /// attach an attestation that signs one result while the host reports
    /// another, and lets a reader notice a record edited after signing.
    pub fn describes(&self, request_id: &str, exit_code: i32, duration_ms: u64) -> bool {
        self.request_id == request_id
            && self.exit_code == exit_code
            && self.duration_ms == duration_ms
    }
}

fn host_attestation_payload(
    version: u8,
    key_id: &str,
    request_id: &str,
    exit_code: i32,
    duration_ms: u64,
) -> Vec<u8> {
    serde_json::to_vec(&(
        "agent-guard/host-attestation",
        version,
        key_id,
        request_id,
        exit_code,
        duration_ms,
    ))
    .expect("host attestation signing payload should always serialize")
}
