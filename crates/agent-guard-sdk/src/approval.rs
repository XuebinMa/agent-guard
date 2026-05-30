//! S7-1: approval ledger — request-id lifecycle for human-in-the-loop asks.
//!
//! When a policy returns `ask_for_approval`, the runtime records a *pending*
//! request here so a separate process (the `agent-guard approve <id>` CLI,
//! S7-2) can approve or deny it out of band, and the asking call can resume
//! (S7-4) once a decision lands.
//!
//! ## Storage: append-only JSONL
//!
//! The ledger is a JSONL event log, not a mutable table. Two independent
//! processes touch it — the agent that creates the pending request and the
//! human running the CLI — so a read-modify-write table would race. Instead
//! **every writer only ever appends one line**; readers fold the event stream
//! into current state. A small `O_APPEND` write is atomic on POSIX, so
//! concurrent appends interleave cleanly without a lock.
//!
//! Two event kinds:
//! - `created` — immutable request facts (id, tool, payload hash, message).
//! - `decided` — a terminal transition (approved / denied / expired).
//!
//! The only residual race is two `decided` lines for one id; `decide` guards
//! against it with a pre-check (sufficient for a local single-user tool) and
//! the fold treats the first terminal decision as authoritative.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Lifecycle state of an approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

impl ApprovalStatus {
    /// True once the request has reached a terminal decision.
    pub fn is_decided(self) -> bool {
        !matches!(self, ApprovalStatus::Pending)
    }
}

/// The folded view of a single approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub request_id: String,
    pub tool: String,
    pub payload_hash: String,
    pub message: String,
    pub agent_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub status: ApprovalStatus,
    pub decided_at: Option<DateTime<Utc>>,
    /// Free-form identifier of who decided (e.g. CLI `--by`), if recorded.
    pub decided_by: Option<String>,
}

#[derive(Debug, Error)]
pub enum ApprovalError {
    #[error("approval ledger I/O error at '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("approval request '{0}' not found")]
    NotFound(String),
    #[error("approval request '{request_id}' is already {status:?}")]
    AlreadyDecided {
        request_id: String,
        status: ApprovalStatus,
    },
}

// ── On-disk event log ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct CreatedEvent {
    request_id: String,
    tool: String,
    payload_hash: String,
    message: String,
    agent_id: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecidedEvent {
    request_id: String,
    status: ApprovalStatus,
    decided_at: DateTime<Utc>,
    decided_by: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum LedgerEvent {
    Created(CreatedEvent),
    Decided(DecidedEvent),
}

// ── Ledger ────────────────────────────────────────────────────────────────────

/// A JSONL-backed approval ledger bound to a single file path.
///
/// Cheap to clone/recreate — it holds only the path and reads the file on each
/// query, so multiple processes can share one ledger file.
#[derive(Debug, Clone)]
pub struct ApprovalLedger {
    path: PathBuf,
}

impl ApprovalLedger {
    /// Open (or lazily create on first write) a ledger at `path`.
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The backing file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Record a new pending approval request and return its folded record.
    pub fn create_pending(
        &self,
        request_id: impl Into<String>,
        tool: impl Into<String>,
        payload_hash: impl Into<String>,
        message: impl Into<String>,
        agent_id: Option<String>,
    ) -> Result<ApprovalRecord, ApprovalError> {
        let created = CreatedEvent {
            request_id: request_id.into(),
            tool: tool.into(),
            payload_hash: payload_hash.into(),
            message: message.into(),
            agent_id,
            created_at: Utc::now(),
        };

        let record = ApprovalRecord {
            request_id: created.request_id.clone(),
            tool: created.tool.clone(),
            payload_hash: created.payload_hash.clone(),
            message: created.message.clone(),
            agent_id: created.agent_id.clone(),
            created_at: created.created_at,
            status: ApprovalStatus::Pending,
            decided_at: None,
            decided_by: None,
        };

        self.append(&LedgerEvent::Created(created))?;
        Ok(record)
    }

    /// Look up a request's current folded state.
    pub fn get(&self, request_id: &str) -> Result<Option<ApprovalRecord>, ApprovalError> {
        Ok(self.fold()?.remove(request_id))
    }

    /// All requests still awaiting a decision, oldest first.
    pub fn list_pending(&self) -> Result<Vec<ApprovalRecord>, ApprovalError> {
        let mut pending: Vec<ApprovalRecord> = self
            .fold()?
            .into_values()
            .filter(|r| r.status == ApprovalStatus::Pending)
            .collect();
        pending.sort_by_key(|r| r.created_at);
        Ok(pending)
    }

    /// Approve a pending request.
    pub fn approve(
        &self,
        request_id: &str,
        decided_by: Option<String>,
    ) -> Result<ApprovalRecord, ApprovalError> {
        self.decide(request_id, ApprovalStatus::Approved, decided_by)
    }

    /// Deny a pending request.
    pub fn deny(
        &self,
        request_id: &str,
        decided_by: Option<String>,
    ) -> Result<ApprovalRecord, ApprovalError> {
        self.decide(request_id, ApprovalStatus::Denied, decided_by)
    }

    /// Apply a terminal decision to a pending request.
    ///
    /// Errors if the request is unknown or already decided. There is a small
    /// TOCTOU window between the pre-check and the append; for a local
    /// single-user tool this is acceptable, and the fold treats the first
    /// terminal decision as authoritative regardless.
    pub fn decide(
        &self,
        request_id: &str,
        status: ApprovalStatus,
        decided_by: Option<String>,
    ) -> Result<ApprovalRecord, ApprovalError> {
        let current = self
            .get(request_id)?
            .ok_or_else(|| ApprovalError::NotFound(request_id.to_string()))?;
        if current.status.is_decided() {
            return Err(ApprovalError::AlreadyDecided {
                request_id: request_id.to_string(),
                status: current.status,
            });
        }

        let decided_at = Utc::now();
        self.append(&LedgerEvent::Decided(DecidedEvent {
            request_id: request_id.to_string(),
            status,
            decided_at,
            decided_by: decided_by.clone(),
        }))?;

        Ok(ApprovalRecord {
            status,
            decided_at: Some(decided_at),
            decided_by,
            ..current
        })
    }

    // ── internals ──────────────────────────────────────────────────────────

    fn append(&self, event: &LedgerEvent) -> Result<(), ApprovalError> {
        // serde_json on owned data with no NaN/Inf cannot fail; map defensively
        // rather than unwrap so a serialiser change never panics a writer.
        let line = serde_json::to_string(event).map_err(|e| ApprovalError::Io {
            path: self.path.clone(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
        })?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|source| ApprovalError::Io {
                path: self.path.clone(),
                source,
            })?;
        writeln!(file, "{line}").map_err(|source| ApprovalError::Io {
            path: self.path.clone(),
            source,
        })
    }

    /// Replay the event log into the current state of every request.
    fn fold(&self) -> Result<BTreeMap<String, ApprovalRecord>, ApprovalError> {
        let contents = match std::fs::read_to_string(&self.path) {
            Ok(s) => s,
            // A ledger that was never written to is simply empty.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(source) => {
                return Err(ApprovalError::Io {
                    path: self.path.clone(),
                    source,
                })
            }
        };

        let mut state: BTreeMap<String, ApprovalRecord> = BTreeMap::new();
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Skip unparseable lines rather than aborting — a partially-written
            // tail line should not make the whole ledger unreadable.
            let Ok(event) = serde_json::from_str::<LedgerEvent>(line) else {
                continue;
            };
            apply_event(&mut state, event);
        }
        Ok(state)
    }
}

fn apply_event(state: &mut BTreeMap<String, ApprovalRecord>, event: LedgerEvent) {
    match event {
        LedgerEvent::Created(c) => {
            state.entry(c.request_id.clone()).or_insert(ApprovalRecord {
                request_id: c.request_id,
                tool: c.tool,
                payload_hash: c.payload_hash,
                message: c.message,
                agent_id: c.agent_id,
                created_at: c.created_at,
                status: ApprovalStatus::Pending,
                decided_at: None,
                decided_by: None,
            });
        }
        LedgerEvent::Decided(d) => {
            if let Some(record) = state.get_mut(&d.request_id) {
                // First terminal decision wins; ignore later contradicting ones.
                if !record.status.is_decided() {
                    record.status = d.status;
                    record.decided_at = Some(d.decided_at);
                    record.decided_by = d.decided_by;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn ledger() -> (tempfile::TempDir, ApprovalLedger) {
        let dir = tempdir().expect("tempdir");
        let ledger = ApprovalLedger::open(dir.path().join("approvals.jsonl"));
        (dir, ledger)
    }

    #[test]
    fn create_then_get_yields_pending() {
        let (_dir, ledger) = ledger();
        ledger
            .create_pending(
                "req-1",
                "bash",
                "abc123",
                "git push origin main",
                Some("a".into()),
            )
            .expect("create");

        let record = ledger.get("req-1").expect("get").expect("present");
        assert_eq!(record.status, ApprovalStatus::Pending);
        assert_eq!(record.tool, "bash");
        assert_eq!(record.agent_id.as_deref(), Some("a"));
        assert!(record.decided_at.is_none());
    }

    #[test]
    fn approve_transitions_to_approved() {
        let (_dir, ledger) = ledger();
        ledger
            .create_pending("req-1", "bash", "h", "msg", None)
            .expect("create");

        let decided = ledger
            .approve("req-1", Some("alice".into()))
            .expect("approve");
        assert_eq!(decided.status, ApprovalStatus::Approved);
        assert_eq!(decided.decided_by.as_deref(), Some("alice"));
        assert!(decided.decided_at.is_some());

        // Persisted across a fresh read.
        let reread = ledger.get("req-1").expect("get").expect("present");
        assert_eq!(reread.status, ApprovalStatus::Approved);
    }

    #[test]
    fn deny_transitions_to_denied() {
        let (_dir, ledger) = ledger();
        ledger
            .create_pending("r", "http_request", "h", "POST", None)
            .expect("create");

        let decided = ledger.deny("r", None).expect("deny");
        assert_eq!(decided.status, ApprovalStatus::Denied);
    }

    #[test]
    fn deciding_twice_is_rejected() {
        let (_dir, ledger) = ledger();
        ledger
            .create_pending("r", "bash", "h", "m", None)
            .expect("create");
        ledger.approve("r", None).expect("first approve");

        let err = ledger
            .deny("r", None)
            .expect_err("second decision must fail");
        assert!(matches!(err, ApprovalError::AlreadyDecided { .. }));

        // The first decision remains authoritative.
        assert_eq!(
            ledger.get("r").unwrap().unwrap().status,
            ApprovalStatus::Approved
        );
    }

    #[test]
    fn deciding_unknown_request_is_not_found() {
        let (_dir, ledger) = ledger();
        let err = ledger
            .approve("ghost", None)
            .expect_err("unknown must fail");
        assert!(matches!(err, ApprovalError::NotFound(_)));
    }

    #[test]
    fn list_pending_excludes_decided_and_sorts_by_age() {
        let (_dir, ledger) = ledger();
        ledger
            .create_pending("a", "bash", "h", "first", None)
            .expect("create a");
        ledger
            .create_pending("b", "bash", "h", "second", None)
            .expect("create b");
        ledger
            .create_pending("c", "bash", "h", "third", None)
            .expect("create c");
        ledger.approve("b", None).expect("approve b");

        let pending = ledger.list_pending().expect("list");
        let ids: Vec<&str> = pending.iter().map(|r| r.request_id.as_str()).collect();
        assert_eq!(ids, vec!["a", "c"]);
    }

    #[test]
    fn missing_ledger_file_reads_as_empty() {
        let (_dir, ledger) = ledger();
        assert!(ledger.get("anything").expect("get").is_none());
        assert!(ledger.list_pending().expect("list").is_empty());
    }

    #[test]
    fn corrupt_lines_are_skipped() {
        let (dir, ledger) = ledger();
        ledger
            .create_pending("r", "bash", "h", "m", None)
            .expect("create");
        // Append a garbage line directly.
        let mut f = OpenOptions::new()
            .append(true)
            .open(dir.path().join("approvals.jsonl"))
            .expect("open");
        writeln!(f, "{{ not valid json").expect("write garbage");

        // Still readable; the valid record survives.
        assert_eq!(
            ledger.get("r").unwrap().unwrap().status,
            ApprovalStatus::Pending
        );
    }
}
