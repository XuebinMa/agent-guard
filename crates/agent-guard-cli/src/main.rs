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
//! And the broker-executed outbound path, where the human sees the resolved
//! effect rather than the command line and the Guard performs the push:
//!
//!   agent-guard push --policy p.yaml --remote origin --branch main
//!
//! The ledger path defaults to `$AGENT_GUARD_APPROVALS` or
//! `<home>/.agent-guard/approvals.jsonl`; override with `--ledger`.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;

use agent_guard_broker::{
    execute_push_with_receipt, issue_grant, resolve_push_transaction, PushAttempt, PushTransaction,
    RefUpdateKind, Witness,
};
use agent_guard_sdk::approval::{
    default_ledger_path, ApprovalError, ApprovalLedger, ApprovalRecord,
};
use agent_guard_sdk::{Context, Guard, GuardDecision, GuardInput, Tool};
use chrono::{Duration, Utc};
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
    /// Resolve, show, authorize and execute one Git push.
    ///
    /// The preview is resolved from the repository and the remote, so it
    /// shows the effect rather than the command line. Between the preview and
    /// the push the transaction is re-resolved and the authorization is spent
    /// against it, so a repository that moved in between is refused rather
    /// than pushed.
    Push {
        /// Policy the push is evaluated against. A `deny` rule matching the
        /// equivalent command refuses before anything else happens.
        ///
        /// Defaults to `$AGENT_GUARD_POLICY`, then to the policy the Claude
        /// Code plugin installs — which is the one that refused the push you
        /// are running this command because of.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Repository to push from.
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long, default_value = "origin")]
        remote: String,
        #[arg(long)]
        branch: String,
        /// Skip the interactive confirmation. The preview is still printed.
        #[arg(long)]
        yes: bool,
        /// Where one-use authorizations are kept.
        #[arg(long)]
        grants: Option<PathBuf>,
        /// Write the receipt here as JSON. It is printed either way.
        #[arg(long)]
        receipt: Option<PathBuf>,
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
        Commands::Push {
            policy,
            repo,
            remote,
            branch,
            yes,
            grants,
            receipt,
        } => run_push(policy, &repo, &remote, &branch, yes, grants, receipt),
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

    /// The hook prints this command verbatim to a human whose push it just
    /// stopped (`guard-hook`'s `broker_hint`). If running it dies on a missing
    /// argument, the refusal has moved the dead end one step later instead of
    /// removing it — which is the whole reason that hint exists.
    ///
    /// The shape the hook prints therefore has to be a shape this CLI accepts,
    /// and that is an invariant spanning two crates that nothing else checks.
    #[test]
    fn the_command_the_hook_prints_is_one_this_cli_accepts() {
        let parsed = Cli::try_parse_from([
            "agent-guard",
            "push",
            "--remote",
            "origin",
            "--branch",
            "main",
        ]);

        assert!(
            parsed.is_ok(),
            "a human runs exactly this after a refusal: {}",
            parsed
                .err()
                .map(|error| error.to_string())
                .unwrap_or_default()
        );
    }

    /// The location `packages/agent-guard-plugin/bin/cli.js` writes the policy
    /// to and wires the hook to read. A push resolved against some other file
    /// would be judged by rules the refusal never applied, so these two paths
    /// are one fact: changing it here means changing it there.
    #[test]
    fn the_default_policy_is_where_the_plugin_installs_it() {
        assert_eq!(
            plugin_policy_path(Path::new("/home/someone")),
            PathBuf::from("/home/someone/.claude/agent-guard/policy.yaml")
        );
    }

    #[test]
    fn approve_flips_pending_to_approved_and_exits_zero() {
        let (_dir, ledger) = ledger();
        ledger
            .create_pending("r1", "bash", "h", "git push", None, None)
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
            .create_pending("r1", "bash", "h", "m", None, None)
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
            .create_pending("r1", "bash", "h", "m", None, None)
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
            .create_pending("r1", "bash", "h", "m", None, None)
            .expect("create");
        assert_eq!(run_list(&ledger), 0);
        assert_eq!(run_show(&ledger, "r1"), 0);
    }
}

/// Resolve, show, authorize and execute one push.
///
/// The order is deliberate and each step can refuse:
///
/// 1. **Policy**, on the equivalent command. A push a policy denies never
///    reaches a human, because asking someone to approve what the policy
///    already refused teaches them to click through refusals.
/// 2. **Preview**, resolved from the repository and the remote. This is the
///    effect, not the command line.
/// 3. **Confirmation**, from a human who has just read that effect.
/// 4. **Execution**, which re-resolves and spends the authorization against
///    what it just resolved. Reading a preview takes seconds, and a
///    repository can move during them.
fn run_push(
    policy: Option<PathBuf>,
    repo: &Path,
    remote: &str,
    branch: &str,
    yes: bool,
    grants: Option<PathBuf>,
    receipt_path: Option<PathBuf>,
) -> i32 {
    let named_by_caller = policy.is_some();
    let policy_path = policy.unwrap_or_else(default_policy_path);

    // A caller who named a path gets the loader's own error: their path is
    // wrong, and only they know what it should have been. A caller who named
    // nothing is usually here because a refusal told them to run this, so the
    // useful thing to say is how to get a policy at all.
    if !named_by_caller && !policy_path.exists() {
        eprintln!(
            "agent-guard: no policy at {}.\n\
             Install one with `npx agent-guard-plugin init`, or name your own \
             with --policy.",
            policy_path.display()
        );
        return 2;
    }

    let guard = match Guard::from_yaml_file(&policy_path) {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!("agent-guard: policy {}: {error}", policy_path.display());
            return 2;
        }
    };

    let equivalent = format!("git push {remote} {branch}");
    let decision = guard.check(&GuardInput {
        tool: Tool::Bash,
        payload: serde_json::json!({ "command": equivalent }).to_string(),
        context: Context {
            working_directory: Some(repo.to_path_buf()),
            ..Default::default()
        },
    });
    if let GuardDecision::Deny { reason } = &decision {
        eprintln!(
            "agent-guard: policy refuses this push: {}",
            reason.message()
        );
        return 1;
    }

    let transaction = match resolve_push_transaction(repo, remote, branch) {
        Ok(transaction) => transaction,
        Err(error) => {
            eprintln!("agent-guard: could not resolve the push: {error}");
            return 2;
        }
    };

    print_preview(&transaction, &policy_path);

    if matches!(transaction.kind, RefUpdateKind::UpToDate) {
        println!("\nNothing to push.");
        return 0;
    }

    if !yes && !confirm() {
        println!("\nNot pushed.");
        return 1;
    }

    let grant_dir = grants.unwrap_or_else(default_grant_dir);
    let policy_hash = guard.policy_version();
    let grant = match issue_grant(
        &grant_dir,
        &transaction,
        &policy_hash,
        &actor(),
        Duration::minutes(5),
    ) {
        Ok(grant) => grant,
        Err(error) => {
            eprintln!("agent-guard: could not record the authorization: {error}");
            return 2;
        }
    };

    let receipt =
        execute_push_with_receipt(repo, &grant_dir, &grant, &policy_hash, Utc::now(), None);

    if let Some(path) = receipt_path {
        match serde_json::to_vec_pretty(&receipt) {
            Ok(body) => {
                if let Err(error) = std::fs::write(&path, body) {
                    eprintln!("agent-guard: could not write the receipt: {error}");
                }
            }
            Err(error) => eprintln!("agent-guard: could not render the receipt: {error}"),
        }
    }

    match &receipt.attempt {
        PushAttempt::Pushed => {
            println!("\nPushed {} to {}/{branch}.", transaction.local_oid, remote);
            if matches!(receipt.witness, Witness::Unsigned) {
                println!(
                    "Receipt is unsigned: no broker signing key is configured, so nobody \
                     else can check this record."
                );
            }
            0
        }
        PushAttempt::Refused { reason } => {
            eprintln!("\nNot pushed: {reason}");
            1
        }
    }
}

/// Show the effect, in the order someone deciding would ask about it.
fn print_preview(tx: &PushTransaction, policy_path: &Path) {
    // Named, even when it was not asked for. Approving a push means approving
    // it under some set of rules, and a default that goes unstated is a rule
    // set the person deciding never saw.
    println!("policy:  {}", policy_path.display());
    println!("remote:  {} ({})", tx.remote, tx.remote_url);
    println!("branch:  {}", tx.branch);
    println!(
        "update:  {}",
        match tx.kind {
            RefUpdateKind::Create => "creates the branch on the remote",
            RefUpdateKind::FastForward => "fast-forward",
            RefUpdateKind::NotFastForward =>
                "NOT a fast-forward: this would discard remote commits",
            RefUpdateKind::UpToDate => "already up to date",
            RefUpdateKind::Undetermined =>
                "cannot be determined: the remote holds objects this repository has not fetched",
        }
    );
    match &tx.remote_oid {
        Some(oid) => println!("remote is at {oid}"),
        None => println!("remote does not have this branch yet"),
    }
    println!("would move it to {}", tx.local_oid);

    match &tx.added_commits {
        Some(commits) if commits.is_empty() => println!("adds no commits"),
        Some(commits) => {
            println!("adds {} commit(s):", commits.len());
            for oid in commits {
                println!("  {oid}");
            }
        }
        // Not "adds no commits": the question could not be answered, and an
        // empty list would read as an answer.
        None => println!("commits added: unknown until this repository fetches the remote"),
    }
}

fn confirm() -> bool {
    print!("\nPush this? [y/N] ");
    if io::stdout().flush().is_err() {
        return false;
    }
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim(), "y" | "Y" | "yes")
}

/// Where the Claude Code plugin installs the policy.
///
/// `packages/agent-guard-plugin/bin/cli.js` writes it here and points the
/// PreToolUse hook at it. That makes this the policy that refused the push a
/// human is running `agent-guard push` because of, so resolving to anything
/// else would judge the push by rules the refusal never applied.
fn plugin_policy_path(home: &Path) -> PathBuf {
    home.join(".claude").join("agent-guard").join("policy.yaml")
}

fn default_policy_path() -> PathBuf {
    std::env::var("AGENT_GUARD_POLICY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| plugin_policy_path(&dirs_home()))
}

fn default_grant_dir() -> PathBuf {
    std::env::var("AGENT_GUARD_GRANTS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs_home().join(".agent-guard").join("grants"))
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn actor() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}
