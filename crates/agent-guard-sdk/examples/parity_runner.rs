//! Cross-language parity runner — Rust ground-truth side.
//!
//! Reads a fixture pair (policy.yaml + scenarios.json), runs each scenario
//! through `Guard::check` and `Guard::decide`, and prints one JSONL line per
//! scenario. The Python and Node runners must produce byte-identical lines.
//!
//! Run: cargo run -p agent-guard-sdk --example parity_runner -- \
//!         tests/cross-language-parity/fixtures/policy.yaml \
//!         tests/cross-language-parity/fixtures/scenarios.json

use std::path::PathBuf;

use agent_guard_sdk::{
    Context, Guard, GuardDecision, GuardInput, RuntimeDecision, Tool, TrustLevel,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct Scenario {
    name: String,
    tool: Tool,
    payload: serde_json::Value,
    context: ScenarioContext,
}

#[derive(Debug, Deserialize, Default)]
struct ScenarioContext {
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    trust_level: Option<String>,
    #[serde(default)]
    working_directory: Option<String>,
}

#[derive(Debug, Serialize)]
struct Output {
    name: String,
    decision: &'static str,
    code: Option<String>,
    runtime_decision: &'static str,
    runtime_code: Option<String>,
}

fn parse_trust(s: Option<&str>) -> TrustLevel {
    match s.unwrap_or("untrusted").to_ascii_lowercase().as_str() {
        "trusted" => TrustLevel::Trusted,
        "admin" => TrustLevel::Admin,
        _ => TrustLevel::Untrusted,
    }
}

fn build_context(c: ScenarioContext) -> Context {
    Context {
        agent_id: c.agent_id,
        actor: c.actor,
        session_id: c.session_id,
        trust_level: parse_trust(c.trust_level.as_deref()),
        working_directory: c.working_directory.map(PathBuf::from),
    }
}

fn decision_label(d: &GuardDecision) -> &'static str {
    match d {
        GuardDecision::Allow => "allow",
        GuardDecision::Deny { .. } => "deny",
        GuardDecision::AskUser { .. } => "ask_user",
    }
}

fn decision_code(d: &GuardDecision) -> Option<String> {
    match d {
        GuardDecision::Allow => None,
        GuardDecision::Deny { reason } => Some(format!("{:?}", reason.code)),
        GuardDecision::AskUser { reason, .. } => Some(format!("{:?}", reason.code)),
    }
}

fn runtime_label(d: &RuntimeDecision) -> &'static str {
    match d {
        RuntimeDecision::Execute => "execute",
        RuntimeDecision::Handoff => "handoff",
        RuntimeDecision::Deny { .. } => "deny",
        RuntimeDecision::AskForApproval { .. } => "ask_for_approval",
    }
}

fn runtime_code(d: &RuntimeDecision) -> Option<String> {
    match d {
        RuntimeDecision::Execute | RuntimeDecision::Handoff => None,
        RuntimeDecision::Deny { reason } => Some(format!("{:?}", reason.code)),
        RuntimeDecision::AskForApproval { reason, .. } => Some(format!("{:?}", reason.code)),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let policy_path = args
        .next()
        .expect("usage: parity_runner <policy.yaml> <scenarios.json>");
    let scenarios_path = args
        .next()
        .expect("usage: parity_runner <policy.yaml> <scenarios.json>");

    let guard = Guard::from_yaml_file(&policy_path)?;
    let scenarios: Vec<Scenario> =
        serde_json::from_str(&std::fs::read_to_string(&scenarios_path)?)?;

    for scenario in scenarios {
        let context = build_context(scenario.context);
        let input = GuardInput {
            tool: scenario.tool.clone(),
            payload: serde_json::to_string(&scenario.payload)?,
            context,
        };

        let decision = guard.check(&input);
        let runtime = guard.decide(&input);

        let out = Output {
            name: scenario.name,
            decision: decision_label(&decision),
            code: decision_code(&decision),
            runtime_decision: runtime_label(&runtime),
            runtime_code: runtime_code(&runtime),
        };
        println!("{}", serde_json::to_string(&out)?);
    }
    Ok(())
}
