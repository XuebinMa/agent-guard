use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyVerificationStatus {
    Unsigned,
    Verified,
    Invalid,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PolicyVerification {
    pub status: PolicyVerificationStatus,
    pub error: Option<String>,
}

impl PolicyVerification {
    pub fn unsigned() -> Self {
        Self {
            status: PolicyVerificationStatus::Unsigned,
            error: None,
        }
    }

    pub fn verified() -> Self {
        Self {
            status: PolicyVerificationStatus::Verified,
            error: None,
        }
    }

    pub fn invalid(error: impl Into<String>) -> Self {
        Self {
            status: PolicyVerificationStatus::Invalid,
            error: Some(error.into()),
        }
    }

    pub fn is_verified(&self) -> bool {
        matches!(self.status, PolicyVerificationStatus::Verified)
    }

    pub fn should_fail_closed(&self) -> bool {
        matches!(self.status, PolicyVerificationStatus::Invalid)
    }

    pub fn status_label(&self) -> &'static str {
        match self.status {
            PolicyVerificationStatus::Unsigned => "unsigned",
            PolicyVerificationStatus::Verified => "verified",
            PolicyVerificationStatus::Invalid => "invalid",
        }
    }
}

pub fn sign_policy(yaml: &str, signing_key: &SigningKey) -> String {
    let signature = signing_key.sign(yaml.as_bytes());
    hex::encode(signature.to_bytes())
}

pub fn verify_policy(yaml: &str, public_key_hex: &str, signature_hex: &str) -> PolicyVerification {
    let public_key_bytes = match decode_fixed_hex::<32>(public_key_hex, "public key") {
        Ok(bytes) => bytes,
        Err(error) => return PolicyVerification::invalid(error),
    };
    let signature_bytes = match decode_signature(signature_hex) {
        Ok(signature) => signature,
        Err(error) => return PolicyVerification::invalid(error),
    };

    let verifying_key = match VerifyingKey::from_bytes(&public_key_bytes) {
        Ok(key) => key,
        Err(error) => {
            return PolicyVerification::invalid(format!("invalid public key bytes: {error}"));
        }
    };

    match verifying_key.verify(yaml.as_bytes(), &signature_bytes) {
        Ok(_) => PolicyVerification::verified(),
        Err(error) => {
            PolicyVerification::invalid(format!("signature verification failed: {error}"))
        }
    }
}

pub fn load_policy_signature_file(path: impl AsRef<Path>) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map(|value| value.trim().to_string())
        .map_err(|error| error.to_string())
}

pub fn load_public_key_file(path: impl AsRef<Path>) -> Result<String, String> {
    load_policy_signature_file(path)
}

pub fn parse_hex_signing_key(hex_key: &str) -> Result<SigningKey, String> {
    let key_bytes = decode_fixed_hex::<32>(hex_key, "private key")?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

fn decode_fixed_hex<const N: usize>(hex_value: &str, label: &str) -> Result<[u8; N], String> {
    let bytes =
        hex::decode(hex_value.trim()).map_err(|error| format!("invalid {label} hex: {error}"))?;
    bytes.try_into().map_err(|value: Vec<u8>| {
        format!(
            "{label} must be exactly {N} bytes ({} hex chars), got {} bytes",
            N * 2,
            value.len()
        )
    })
}

fn decode_signature(signature_hex: &str) -> Result<Signature, String> {
    let bytes = hex::decode(signature_hex.trim())
        .map_err(|error| format!("invalid signature hex: {error}"))?;
    Signature::from_slice(&bytes).map_err(|error| format!("invalid signature bytes: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{parse_hex_signing_key, sign_policy, verify_policy, PolicyVerificationStatus};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn signs_and_verifies_policy_yaml() {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let signature = sign_policy("version: 1\n", &signing_key);

        let verification = verify_policy("version: 1\n", &public_key_hex, &signature);
        assert_eq!(verification.status, PolicyVerificationStatus::Verified);
        assert!(verification.error.is_none());
    }

    #[test]
    fn reports_invalid_policy_signature() {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let signature = sign_policy("version: 1\n", &signing_key);

        let verification = verify_policy("version: 2\n", &public_key_hex, &signature);
        assert_eq!(verification.status, PolicyVerificationStatus::Invalid);
        assert!(verification.error.is_some());
    }

    #[test]
    fn parses_hex_signing_key() {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let private_key_hex = hex::encode(signing_key.to_bytes());
        let parsed = parse_hex_signing_key(&private_key_hex).expect("signing key should parse");
        assert_eq!(parsed.to_bytes(), signing_key.to_bytes());
    }
}
