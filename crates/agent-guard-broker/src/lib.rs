//! Broker-owned Git push.
//!
//! The target this crate exists for: an agent may write and test freely, and
//! agent-guard decides and executes which exact Git change leaves the machine.
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
//! and the remote. What it returns is what an approval is about.
//!
//! ## The order the pieces run in
//!
//! 1. [`resolve_push_transaction`] — what the push would actually do, read
//!    from the remote rather than from a local tracking ref.
//! 2. [`issue_grant`] — a human decision about that one transaction, bound to
//!    its digest, the policy hash in force, an actor and a deadline.
//! 3. [`execute_push`] — resolve again, spend the grant against what was just
//!    resolved, and push with both ends pinned. Authorization and drift
//!    detection are one check rather than two: a transaction that moved no
//!    longer matches the digest its grant is bound to and cannot be spent, so
//!    there is no separate drift step to forget to call.
//! 4. [`execute_push_with_receipt`] — the same, recording what the broker
//!    witnessed, for refusals as much as for pushes.
//!
//! Only fast-forwards and branch creates execute. Force, mirror, remote
//! branch removal, tags and multiple refspecs are not performed here, and
//! fail closed rather than degrading into something adjacent.
//!
//! ## What the caller still owns
//!
//! Policy is evaluated above this crate, not inside it, and so is obtaining
//! the human decision — `agent-guard push` in `agent-guard-cli` is the entry
//! point that does both. What this crate enforces is that the policy has not
//! changed since: a grant records the hash it was issued under, spending
//! presents the hash in force at execution, and an approval issued under a
//! policy that has since been edited is refused rather than honoured.
//!
//! ## What this does not establish
//!
//! Credential isolation is a deployment property this code cannot verify.
//! The push uses whatever credential the broker process holds, which is a
//! boundary only if the agent has none of its own. Nothing here can check
//! that, and nothing here stops an agent holding a credential of its own from
//! pushing without a grant at all.
//!
//! A receipt sealed with no signing key is [`Witness::Unsigned`]: a truthful
//! record of what happened, and not evidence anyone else can check. The two
//! must not be read as the same thing.

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
