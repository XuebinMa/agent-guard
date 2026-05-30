//! `agent-guard` CLI — approval workflow (S7-2).
//!
//! Decides the pending `ask_for_approval` requests recorded in the approval
//! ledger by the runtime (S7-1). A human runs:
//!
//!   agent-guard list                 # show what is waiting
//!   agent-guard show <request-id>     # inspect one request
//!   agent-guard approve <request-id>  # let it proceed
//!   agent-guard deny <request-id>     # block it
//!
//! The ledger path defaults to `$AGENT_GUARD_APPROVALS` or
//! `<home>/.agent-guard/approvals.jsonl`; override with `--ledger`.

use std::path::PathBuf;
use std::process;

use agent_guard_sdk::approval::{
    default_ledger_path, ApprovalError, ApprovalLedger, ApprovalRecord,
};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "agent-guard",
    version,
    about = "agent-guard approval workflow CLI"
)]
struct Cli {
    /// Path to the approval ledger. Defaults to `$AGENT_GUARD_APPROVALS`, then
    /// `<home>/.agent-guard/approvals.jsonl`.
    #[arg(long, global = true)]
    ledger: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List pending approval requests.
    List,
    /// Show a single request by id.
    Show {
        /// The request id to inspect.
        request_id: String,
    },
    /// Approve a pending request so the asking call may proceed.
    Approve {
        /// The request id to approve.
        request_id: String,
        /// Optional identifier of who approved (recorded in the ledger).
        #[arg(long)]
        by: Option<String>,
    },
    /// Deny a pending request.
    Deny {
        /// The request id to deny.
        request_id: String,
        /// Optional identifier of who denied (recorded in the ledger).
        #[arg(long)]
        by: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    let ledger = ApprovalLedger::open(cli.ledger.unwrap_or_else(default_ledger_path));

    let exit_code = match cli.command {
        Commands::List => run_list(&ledger),
        Commands::Show { request_id } => run_show(&ledger, &request_id),
        Commands::Approve { request_id, by } => {
            run_decision(&ledger, &request_id, by, Decision::Approve)
        }
        Commands::Deny { request_id, by } => run_decision(&ledger, &request_id, by, Decision::Deny),
    };
    process::exit(exit_code);
}

enum Decision {
    Approve,
    Deny,
}

fn run_list(ledger: &ApprovalLedger) -> i32 {
    match ledger.list_pending() {
        Ok(pending) if pending.is_empty() => {
            println!("No pending approval requests.");
            0
        }
        Ok(pending) => {
            println!(
                "{:<26} {:<12} {:<26} MESSAGE",
                "REQUEST_ID", "TOOL", "CREATED"
            );
            for record in pending {
                println!(
                    "{:<26} {:<12} {:<26} {}",
                    record.request_id,
                    record.tool,
                    record.created_at.to_rfc3339(),
                    record.message
                );
            }
            0
        }
        Err(e) => fail(&e),
    }
}

fn run_show(ledger: &ApprovalLedger, request_id: &str) -> i32 {
    match ledger.get(request_id) {
        Ok(Some(record)) => {
            print_record(&record);
            0
        }
        Ok(None) => {
            eprintln!("error: approval request '{request_id}' not found");
            1
        }
        Err(e) => fail(&e),
    }
}

fn run_decision(
    ledger: &ApprovalLedger,
    request_id: &str,
    by: Option<String>,
    decision: Decision,
) -> i32 {
    let result = match decision {
        Decision::Approve => ledger.approve(request_id, by),
        Decision::Deny => ledger.deny(request_id, by),
    };
    match result {
        Ok(record) => {
            println!(
                "{} request '{}' ({}).",
                verb_past(&decision),
                record.request_id,
                record.tool
            );
            0
        }
        Err(e) => fail(&e),
    }
}

fn verb_past(decision: &Decision) -> &'static str {
    match decision {
        Decision::Approve => "Approved",
        Decision::Deny => "Denied",
    }
}

fn print_record(record: &ApprovalRecord) {
    println!("request_id:   {}", record.request_id);
    println!("tool:         {}", record.tool);
    println!("status:       {:?}", record.status);
    println!(
        "agent_id:     {}",
        record.agent_id.as_deref().unwrap_or("-")
    );
    println!("created_at:   {}", record.created_at.to_rfc3339());
    if let Some(decided_at) = record.decided_at {
        println!("decided_at:   {}", decided_at.to_rfc3339());
    }
    if let Some(by) = &record.decided_by {
        println!("decided_by:   {by}");
    }
    println!("payload_hash: {}", record.payload_hash);
    println!("message:      {}", record.message);
}

fn fail(error: &ApprovalError) -> i32 {
    eprintln!("error: {error}");
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_guard_sdk::approval::ApprovalStatus;
    use tempfile::tempdir;

    fn ledger() -> (tempfile::TempDir, ApprovalLedger) {
        let dir = tempdir().expect("tempdir");
        let ledger = ApprovalLedger::open(dir.path().join("approvals.jsonl"));
        (dir, ledger)
    }

    #[test]
    fn approve_flips_pending_to_approved_and_exits_zero() {
        let (_dir, ledger) = ledger();
        ledger
            .create_pending("r1", "bash", "h", "git push", None)
            .expect("create");

        let code = run_decision(&ledger, "r1", Some("alice".into()), Decision::Approve);

        assert_eq!(code, 0);
        let record = ledger.get("r1").unwrap().unwrap();
        assert_eq!(record.status, ApprovalStatus::Approved);
        assert_eq!(record.decided_by.as_deref(), Some("alice"));
    }

    #[test]
    fn deny_flips_pending_to_denied() {
        let (_dir, ledger) = ledger();
        ledger
            .create_pending("r1", "bash", "h", "m", None)
            .expect("create");

        let code = run_decision(&ledger, "r1", None, Decision::Deny);

        assert_eq!(code, 0);
        assert_eq!(
            ledger.get("r1").unwrap().unwrap().status,
            ApprovalStatus::Denied
        );
    }

    #[test]
    fn deciding_unknown_request_exits_nonzero() {
        let (_dir, ledger) = ledger();
        assert_eq!(run_decision(&ledger, "ghost", None, Decision::Approve), 1);
    }

    #[test]
    fn deciding_twice_exits_nonzero() {
        let (_dir, ledger) = ledger();
        ledger
            .create_pending("r1", "bash", "h", "m", None)
            .expect("create");
        assert_eq!(run_decision(&ledger, "r1", None, Decision::Approve), 0);
        assert_eq!(run_decision(&ledger, "r1", None, Decision::Deny), 1);
    }

    #[test]
    fn show_missing_request_exits_nonzero() {
        let (_dir, ledger) = ledger();
        assert_eq!(run_show(&ledger, "ghost"), 1);
    }

    #[test]
    fn list_and_show_present_existing_requests() {
        let (_dir, ledger) = ledger();
        ledger
            .create_pending("r1", "bash", "h", "m", None)
            .expect("create");
        assert_eq!(run_list(&ledger), 0);
        assert_eq!(run_show(&ledger, "r1"), 0);
    }
}
