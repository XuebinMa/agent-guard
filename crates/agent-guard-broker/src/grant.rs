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
    /// The complete transaction shown to the approver.
    ///
    /// Version 1 grants did not carry this field. They remain readable and
    /// can still be checked by the compatibility `spend_grant` API when its
    /// caller presents a complete transaction, but the broker executor must
    /// refuse them: without the approved URL and local OID it cannot prove a
    /// repository has not redirected it before the first remote query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<PushTransaction>,
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
    #[error("grant schema version {version} is not supported")]
    UnsupportedVersion { version: u8 },
    #[error(
        "grant schema version {version} does not retain the approved transaction required for safe execution"
    )]
    MissingApprovedTransaction { version: u8 },
}

/// Reject anything that is not one plain filename, so a caller cannot reach
/// outside the grant directory by naming a path.
///
/// The grammar is checked against the raw `id`, not against
/// `Path::components()`, which normalises a trailing separator or a `.` segment
/// away and so would accept an `id` such as `"a/"` whose joined form
/// (`a/.json`) still contains a separator. Issued ids are UUIDs, so a strict
/// `[A-Za-z0-9._-]` grammar that forbids separators and the `.`/`..` names is
/// both sufficient and unambiguous.
fn grant_path(dir: &Path, id: &str) -> Result<PathBuf, GrantError> {
    let safe = !id.is_empty()
        && id != "."
        && id != ".."
        && id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'));
    if !safe {
        return Err(GrantError::InvalidId { id: id.to_string() });
    }
    Ok(dir.join(format!("{id}.json")))
}

pub(crate) fn grant_was_spent(dir: &Path, id: &str) -> bool {
    grant_path(&dir.join("spent"), id).is_ok_and(|path| path.is_file())
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
    restrict_directory(dir)?;

    let issued_at = Utc::now();
    let grant = PushGrant {
        version: 2,
        grant_id: uuid::Uuid::new_v4().to_string(),
        transaction_digest: transaction.digest(),
        transaction: Some(transaction.clone()),
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
    write_grant_file(&path, &body)?;

    Ok(grant.grant_id)
}

/// Write the grant to a temporary sibling and rename it into place, so a
/// concurrent claim never observes a half-written grant, and create it readable
/// only by the issuing user. A grant is a one-use authorization; its contents
/// and its id are a capability that other local users should not be able to
/// read.
fn write_grant_file(path: &Path, body: &[u8]) -> Result<(), GrantError> {
    use std::io::Write;

    let tmp = path.with_extension("json.tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(body)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Tighten the grant directory to the issuing user only.
#[cfg(unix)]
fn restrict_directory(dir: &Path) -> Result<(), GrantError> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(dir)?.permissions();
    if perms.mode() & 0o077 != 0 {
        perms.set_mode(0o700);
        std::fs::set_permissions(dir, perms)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn restrict_directory(_dir: &Path) -> Result<(), GrantError> {
    Ok(())
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
    let grant = claim_grant(dir, id, policy_hash, now)?;

    let presented_digest = presented.digest();
    if grant.transaction_digest != presented_digest {
        return Err(GrantError::TransactionMismatch {
            approved: grant.transaction_digest,
            presented: presented_digest,
        });
    }

    Ok(grant)
}

/// Atomically claim a grant and validate the facts that do not require
/// inspecting a repository or contacting a remote.
///
/// The rename is deliberately the first operation. Once a caller presents a
/// grant id, policy drift, expiry, corruption, or later repository drift all
/// burn that approval rather than leaving it reusable as a network oracle.
pub(crate) fn claim_grant(
    dir: &Path,
    id: &str,
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

    if grant.grant_id != id {
        return Err(GrantError::Corrupt {
            id: id.to_string(),
            detail: format!(
                "embedded grant id {:?} does not match its filename",
                grant.grant_id
            ),
        });
    }

    if !matches!(grant.version, 1 | 2) {
        return Err(GrantError::UnsupportedVersion {
            version: grant.version,
        });
    }

    if grant.version == 2 {
        let approved =
            grant
                .transaction
                .as_ref()
                .ok_or(GrantError::MissingApprovedTransaction {
                    version: grant.version,
                })?;
        let approved_digest = approved.digest();
        if approved_digest != grant.transaction_digest {
            return Err(GrantError::Corrupt {
                id: id.to_string(),
                detail: format!(
                    "stored transaction digest {approved_digest} does not match recorded digest {}",
                    grant.transaction_digest
                ),
            });
        }
        if grant.remote != approved.remote || grant.branch != approved.branch {
            return Err(GrantError::Corrupt {
                id: id.to_string(),
                detail: "stored transaction target does not match the grant target".to_string(),
            });
        }
    }

    if grant.policy_hash != policy_hash {
        return Err(GrantError::PolicyChanged {
            issued_under: grant.policy_hash,
            now: policy_hash.to_string(),
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
