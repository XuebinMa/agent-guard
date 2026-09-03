//! What the broker witnessed.
//!
//! ## A receipt is emitted for every attempt
//!
//! Including refusals, and including runs with no signing key. The one thing
//! a receipt must never be is absent: an operator reading "no receipt" will
//! conclude "no push was attempted", and reaching that conclusion because a
//! key was not configured is being misled by their own tooling. That failure
//! has a precedent in this repository — anomaly records went to a sink most
//! deployments do not configure, so a consumer counting them read zero
//! forever.
//!
//! Refusals matter most of all. The interesting thing a broker does is
//! decline, and a record covering only successes cannot show it happened.
//!
//! ## Witnessed here, unlike a host-reported outcome
//!
//! The broker ran the push itself, so this is a witness rather than a
//! transcription. That is the opposite end from [`HostAttestation`], where
//! the work happened outside the boundary and the most that can be recorded
//! is what a host claimed. The distinction is in the type, not in a field a
//! reader has to know to check.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::transaction::PushTransaction;

/// What happened to the attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum PushAttempt {
    /// The broker ran the push and git accepted it.
    Pushed,
    /// The broker declined, or git refused. The reason is carried because a
    /// refusal without one cannot be acted on.
    Refused { reason: String },
}

/// Whether anyone can check this receipt, and how.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Witness {
    /// Signed by the broker's key. A third party holding the public key can
    /// check that this receipt is the one the broker emitted.
    Signed { signature: String },
    /// The broker witnessed the attempt but no key was configured, so nothing
    /// here is checkable by anyone else. Stated rather than implied by the
    /// absence of a signature field.
    Unsigned,
}

/// The record of one broker-executed push attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushReceipt {
    pub version: u8,
    pub at: DateTime<Utc>,
    /// The transaction as resolved immediately before the attempt.
    ///
    /// `None` when the attempt was refused before anything could be
    /// resolved — a grant id that names nothing, for instance. Such an
    /// attempt still happened and is still recorded; it simply has no effect
    /// to describe.
    pub transaction: Option<PushTransaction>,
    /// The grant this was executed under, when one was spent. `None` for an
    /// attempt refused before any grant could be spent.
    pub grant_id: Option<String>,
    pub attempt: PushAttempt,
    pub witness: Witness,
}

impl PushReceipt {
    /// Sign, or record that nothing signed it.
    pub(crate) fn seal(mut self, key: Option<&SigningKey>) -> Self {
        self.witness = match key {
            Some(key) => Witness::Signed {
                signature: hex::encode(key.sign(&self.preimage()).to_bytes()),
            },
            None => Witness::Unsigned,
        };
        self
    }

    /// Check the signature against the broker's public key.
    ///
    /// An unsigned receipt never verifies. It is a truthful record of a
    /// witnessed attempt and is worth keeping, but it is not evidence anyone
    /// else can rely on, and this must not blur the two.
    pub fn verify(&self, key: &VerifyingKey) -> bool {
        let Witness::Signed { signature } = &self.witness else {
            return false;
        };
        let Ok(bytes) = hex::decode(signature) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&bytes) else {
            return false;
        };
        key.verify(&self.preimage(), &signature).is_ok()
    }

    /// The bytes the signature covers.
    ///
    /// Restated field by field rather than serialized wholesale, so what is
    /// covered is readable here and a field added later cannot widen it
    /// silently. The witness itself is excluded: it carries the signature.
    fn preimage(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            "agent-guard/push-receipt/v1",
            self.version,
            self.at.to_rfc3339(),
            self.transaction.as_ref().map(PushTransaction::digest),
            &self.grant_id,
            &self.attempt,
        ))
        .expect("push receipt preimage should always serialize")
    }
}
