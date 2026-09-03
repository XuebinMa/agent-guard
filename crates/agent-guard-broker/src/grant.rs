//! One-use authorization for one resolved transaction.
//!
//! ## Spending is a rename
//!
//! A grant is a file. Spending it renames that file into a sibling
//! `spent/` directory, and `rename` within a filesystem is one atomic
//! operation: of many callers racing for the same grant, exactly one syscall
//! succeeds and the rest get "no such file". Nothing here reads the grant to
//! decide whether it is still available, because a read followed by a write
//! has a window between them, and that window is the whole of what one-use
//! has to exclude.
//!
//! The spent file is kept rather than deleted. A grant that authorized a push
//! is evidence about that push.
//!
//! ## Spending happens before validation, deliberately
//!
//! A presented grant is consumed whether or not it turns out to authorize
//! what was presented. That looks harsh — a wrong presentation burns an
//! approval the human issued — but the only reasons validation fails are that
//! the effect changed since approval or that someone is probing, and both
//! require a fresh human decision anyway. Validating first would leave a
//! window in which one approval can be tried against many transactions.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::transaction::PushTransaction;

/// A human decision about exactly one transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushGrant {
    pub version: u8,
    /// Names this grant. Also its filename, so it may not contain a path.
    pub grant_id: String,
    /// The digest of the transaction the human approved.
    pub transaction_digest: String,
    /// The policy in force when it was issued.
    pub policy_hash: String,
    /// Which push this is about. Carried so the executor knows what to
    /// resolve before it spends anything; the digest is what authenticates.
    pub remote: String,
    pub branch: String,
    /// Who approved, as recorded by the issuer.
    pub actor: String,
    pub issued_at: DateTime<Utc>,
    /// When this stops being answerable.
    ///
    /// Recorded rather than derived from a timeout the reader would have to
    /// know: someone holding a spent grant can check that a refusal for
    /// expiry was correct, which they cannot do if the deadline lived only in
    /// the process that enforced it.
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Error)]
pub enum GrantError {
    #[error("grant id {id:?} is not a single path segment")]
    InvalidId { id: String },
    #[error("no unspent grant {id:?}")]
    NotFound { id: String },
    #[error("grant is for a different transaction: approved {approved}, presented {presented}")]
    TransactionMismatch { approved: String, presented: String },
    #[error("policy changed since the grant was issued: {issued_under} -> {now}")]
    PolicyChanged { issued_under: String, now: String },
    #[error("grant expired at {expires_at}, presented at {at}")]
    Expired {
        expires_at: DateTime<Utc>,
        at: DateTime<Utc>,
    },
    #[error("grant store: {0}")]
    Io(#[from] std::io::Error),
    #[error("grant {id:?} is not readable as a grant: {detail}")]
    Corrupt { id: String, detail: String },
}

/// Reject anything that is not one plain filename, so a caller cannot reach
/// outside the grant directory by naming a path.
fn grant_path(dir: &Path, id: &str) -> Result<PathBuf, GrantError> {
    let mut components = Path::new(id).components();
    let single = matches!(
        (components.next(), components.next()),
        (Some(std::path::Component::Normal(_)), None)
    );
    if !single || id.is_empty() {
        return Err(GrantError::InvalidId { id: id.to_string() });
    }
    Ok(dir.join(format!("{id}.json")))
}

/// Record a human decision about `transaction` and return the grant id.
pub fn issue_grant(
    dir: &Path,
    transaction: &PushTransaction,
    policy_hash: &str,
    actor: &str,
    ttl: Duration,
) -> Result<String, GrantError> {
    std::fs::create_dir_all(dir)?;

    let issued_at = Utc::now();
    let grant = PushGrant {
        version: 1,
        grant_id: uuid::Uuid::new_v4().to_string(),
        transaction_digest: transaction.digest(),
        policy_hash: policy_hash.to_string(),
        remote: transaction.remote.clone(),
        branch: transaction.branch.clone(),
        actor: actor.to_string(),
        issued_at,
        expires_at: issued_at + ttl,
    };

    let path = grant_path(dir, &grant.grant_id)?;
    let body = serde_json::to_vec_pretty(&grant).map_err(|e| GrantError::Corrupt {
        id: grant.grant_id.clone(),
        detail: e.to_string(),
    })?;
    std::fs::write(&path, body)?;

    Ok(grant.grant_id)
}

/// Read a grant without spending it.
///
/// Advisory only. It answers "which push is this grant about?" so a caller
/// knows what to resolve, and nothing read here is trusted: the spend that
/// follows compares the digest, which covers every field that defines the
/// effect. A grant edited between this read and that spend fails there.
pub fn peek_grant(dir: &Path, id: &str) -> Result<PushGrant, GrantError> {
    let path = grant_path(dir, id)?;
    let body = match std::fs::read(&path) {
        Ok(body) => body,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(GrantError::NotFound { id: id.to_string() })
        }
        Err(e) => return Err(GrantError::Io(e)),
    };
    serde_json::from_slice(&body).map_err(|e| GrantError::Corrupt {
        id: id.to_string(),
        detail: e.to_string(),
    })
}

/// Spend the grant and check that it authorizes what is being presented.
///
/// `now` is a parameter so a caller can be tested against a deadline without
/// waiting for it, and so the instant a decision was made against is the
/// instant that gets recorded rather than one read later.
pub fn spend_grant(
    dir: &Path,
    id: &str,
    presented: &PushTransaction,
    policy_hash: &str,
    now: DateTime<Utc>,
) -> Result<PushGrant, GrantError> {
    let path = grant_path(dir, id)?;
    let spent_dir = dir.join("spent");
    std::fs::create_dir_all(&spent_dir)?;
    let spent_path = grant_path(&spent_dir, id)?;

    // The one atomic step. Whoever wins this rename holds the grant; everyone
    // else sees it gone. No read precedes it, because a read would create the
    // window this exists to close.
    match std::fs::rename(&path, &spent_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(GrantError::NotFound { id: id.to_string() })
        }
        Err(e) => return Err(GrantError::Io(e)),
    }

    let body = std::fs::read(&spent_path)?;
    let grant: PushGrant = serde_json::from_slice(&body).map_err(|e| GrantError::Corrupt {
        id: id.to_string(),
        detail: e.to_string(),
    })?;

    if grant.policy_hash != policy_hash {
        return Err(GrantError::PolicyChanged {
            issued_under: grant.policy_hash,
            now: policy_hash.to_string(),
        });
    }

    let presented_digest = presented.digest();
    if grant.transaction_digest != presented_digest {
        return Err(GrantError::TransactionMismatch {
            approved: grant.transaction_digest,
            presented: presented_digest,
        });
    }

    if now > grant.expires_at {
        return Err(GrantError::Expired {
            expires_at: grant.expires_at,
            at: now,
        });
    }

    Ok(grant)
}
