//! Claude Code PreToolUse hook adapter.
//!
//! Reads a Claude Code PreToolUse JSON payload from stdin, maps the
//! `tool_name` to an agent-guard `Tool`, runs `Guard::check`, and writes
//! the hook response JSON to stdout.
//!
//! Design rules (do not relax without explicit decision):
//! - Never block the user workflow on internal error. On any failure path
//!   (bad stdin, unreadable policy, mapping error), emit `{"decision":"approve"}`
//!   and log the cause to stderr. The `AuditFileWriter` is the durable
//!   record; CC must not stall waiting for us.
//! - Honour the `AGENT_GUARD_HOOK=off` env var as a hard kill switch.
//!   First check before any I/O.
//! - Exit code is always 0. The JSON body carries the decision.

use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod hook;

use hook::{emit_approve, run_check};

#[derive(Parser)]
#[command(name = "guard-hook", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Evaluate a Claude Code PreToolUse payload from stdin.
    Check {
        /// Path to the policy YAML file.
        #[arg(short, long)]
        policy: PathBuf,
        /// Agent identifier reported in audit context.
        #[arg(long, default_value = "claude-code-dogfood")]
        agent_id: String,
    },
}

fn main() -> ExitCode {
    if std::env::var("AGENT_GUARD_HOOK").as_deref() == Ok("off") {
        emit_approve(&mut io::stdout().lock());
        return ExitCode::SUCCESS;
    }

    let cli = Cli::parse();
    let Commands::Check { policy, agent_id } = cli.command;

    let mut stdin_buf = String::new();
    if let Err(error) = io::stdin().read_to_string(&mut stdin_buf) {
        eprintln!("guard-hook: stdin read failed: {error}; defaulting to approve");
        emit_approve(&mut io::stdout().lock());
        return ExitCode::SUCCESS;
    }

    run_check(&stdin_buf, &policy, &agent_id, &mut io::stdout().lock());
    ExitCode::SUCCESS
}
