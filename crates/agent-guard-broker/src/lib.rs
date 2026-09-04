//! Broker-owned Git push.
//!
//! The target this crate exists for: an agent may write and test freely, and
//! agent-guard decides and executes which exact Git change leaves the machine.
//! What ships here today is the first of the five properties that requires —
//! the exact transaction — and nothing else pretends to be present.
//!
//! ## Why the command line is not the transaction
//!
//! `git push origin main` is a request, not a description of an effect. It
//! does not say which URL `origin` resolves to, what the remote currently
//! holds, which commits the remote would gain, or whether the update can be
//! applied without discarding history. A preview built by restating the
//! command shows a human the same string the agent typed, and asks them to
//! approve something neither of them has seen.
//!
//! [`resolve_push_transaction`] answers those questions from the repository
//! and the remote. What it returns is what an approval would be about.
//!
//! ## What this is not yet
//!
//! No credential handling, no authorization, no execution, no receipt. A
//! resolved transaction is a description; nothing here can push, and nothing
//! here prevents an agent that holds a credential from pushing on its own.
//! Those are separate properties and they are not implemented.

mod execute;
mod git;
mod grant;
mod receipt;
mod transaction;

pub use execute::{execute_push, execute_push_with_receipt, ExecuteError, PushOutcome};
pub use git::GitError;
pub use grant::{issue_grant, peek_grant, spend_grant, GrantError, PushGrant};
pub use receipt::{PushAttempt, PushReceipt, Witness};
pub use transaction::{
    drift_against, resolve_push_transaction, Drift, PushTransaction, RefUpdateKind,
};
