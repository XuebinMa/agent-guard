//! S6-5: compliance-evidence report.
//!
//! Aggregates an audit JSONL log (a stream of [`AuditRecord`] lines) into a
//! flat, serialisable summary suitable as control evidence: what was allowed
//! vs denied, why (by code and tool), what the content layer caught, and which
//! policy versions / agents produced the activity over a time window.
//!
//! This is distinct from `verify-log`, which cryptographically verifies signed
//! execution receipts. The report answers "what did the boundary do", the
//! receipt log answers "can we prove a specific execution happened".

use std::collections::{BTreeMap, BTreeSet};

use agent_guard_core::{AuditDecision, AuditRecord};
use chrono::{DateTime, Utc};
use serde::Serialize;

/// A flat, archival summary of audit activity over a window.
#[derive(Debug, Default, Serialize)]
pub struct ComplianceReport {
    /// RFC3339 timestamp the report was generated.
    pub generated_at: String,
    /// The `--since` argument echoed back (e.g. `"7d"`), or `null` for "all".
    pub window_since: Option<String>,
    /// The `--agent-id` filter applied, if any.
    pub agent_filter: Option<String>,
    /// Earliest / latest event timestamp included (RFC3339).
    pub earliest_event: Option<String>,
    pub latest_event: Option<String>,

    /// Records included after filtering, and lines that failed to parse.
    pub records_total: usize,
    pub parse_errors: usize,

    /// Decision evidence (from `tool_call` records).
    pub tool_calls: usize,
    pub allow: usize,
    pub deny: usize,
    pub ask: usize,
    pub denials_by_code: BTreeMap<String, usize>,
    pub denials_by_tool: BTreeMap<String, usize>,

    /// Content-layer evidence (from `content_finding` records).
    pub content_findings: usize,
    pub content_by_mode: BTreeMap<String, usize>,
    pub content_by_label: BTreeMap<String, usize>,

    /// Execution and safety-net evidence.
    pub executions_started: usize,
    pub executions_finished: usize,
    pub sandbox_failures: usize,
    pub anomalies_triggered: usize,
    pub agents_locked: usize,

    /// Distinct policy versions and agents observed in the window.
    pub policy_versions: Vec<String>,
    pub agents: Vec<String>,
}

/// Build a report from raw JSONL `contents`.
///
/// `cutoff` is an inclusive lower-bound Unix timestamp (from `--since`); when
/// `None`, every record is included. `agent_filter` restricts to records whose
/// `agent_id` matches. `since_arg` is echoed into the report for provenance.
pub fn build_report(
    contents: &str,
    cutoff: Option<u64>,
    agent_filter: Option<&str>,
    since_arg: Option<&str>,
) -> ComplianceReport {
    let mut report = ComplianceReport {
        generated_at: Utc::now().to_rfc3339(),
        window_since: since_arg.map(str::to_string),
        agent_filter: agent_filter.map(str::to_string),
        ..ComplianceReport::default()
    };

    let mut policy_versions = BTreeSet::new();
    let mut agents = BTreeSet::new();
    let mut earliest: Option<DateTime<Utc>> = None;
    let mut latest: Option<DateTime<Utc>> = None;

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: AuditRecord = match serde_json::from_str(line) {
            Ok(rec) => rec,
            Err(_) => {
                report.parse_errors += 1;
                continue;
            }
        };

        let (timestamp, agent) = record_meta(&record);
        if let Some(cut) = cutoff {
            if (timestamp.timestamp().max(0) as u64) < cut {
                continue;
            }
        }
        if let Some(want) = agent_filter {
            if agent != Some(want) {
                continue;
            }
        }

        report.records_total += 1;
        earliest = Some(earliest.map_or(timestamp, |e| e.min(timestamp)));
        latest = Some(latest.map_or(timestamp, |l| l.max(timestamp)));
        if let Some(a) = agent {
            agents.insert(a.to_string());
        }

        match &record {
            AuditRecord::ToolCall(event) => {
                report.tool_calls += 1;
                policy_versions.insert(event.policy_version.clone());
                match event.decision {
                    AuditDecision::Allow => report.allow += 1,
                    AuditDecision::Deny => {
                        report.deny += 1;
                        let code = event
                            .code
                            .as_ref()
                            .map(code_label)
                            .unwrap_or_else(|| "UNKNOWN".to_string());
                        *report.denials_by_code.entry(code).or_default() += 1;
                        *report
                            .denials_by_tool
                            .entry(event.tool.clone())
                            .or_default() += 1;
                    }
                    AuditDecision::AskUser => report.ask += 1,
                }
            }
            AuditRecord::ContentFinding(event) => {
                report.content_findings += 1;
                *report
                    .content_by_mode
                    .entry(event.mode.clone())
                    .or_default() += 1;
                for label in &event.labels {
                    *report.content_by_label.entry(label.clone()).or_default() += 1;
                }
            }
            AuditRecord::ExecutionStarted(_) => report.executions_started += 1,
            AuditRecord::ExecutionFinished(_) => report.executions_finished += 1,
            AuditRecord::SandboxFailure(_) => report.sandbox_failures += 1,
            AuditRecord::AnomalyTriggered(_) => report.anomalies_triggered += 1,
            AuditRecord::AgentLocked(_) => report.agents_locked += 1,
            // Policy reloads are operational, not control evidence.
            AuditRecord::PolicyReload(_) => {}
        }
    }

    report.earliest_event = earliest.map(|t| t.to_rfc3339());
    report.latest_event = latest.map(|t| t.to_rfc3339());
    report.policy_versions = policy_versions.into_iter().collect();
    report.agents = agents.into_iter().collect();
    report
}

/// Extract the timestamp and agent_id used for filtering, per record variant.
fn record_meta(record: &AuditRecord) -> (DateTime<Utc>, Option<&str>) {
    match record {
        AuditRecord::ToolCall(e) => (e.timestamp, e.agent_id.as_deref()),
        AuditRecord::ContentFinding(e) => (e.timestamp, e.agent_id.as_deref()),
        AuditRecord::ExecutionStarted(e) | AuditRecord::ExecutionFinished(e) => {
            (e.timestamp, e.agent_id.as_deref())
        }
        AuditRecord::SandboxFailure(e) => (e.timestamp, e.agent_id.as_deref()),
        AuditRecord::AnomalyTriggered(e) | AuditRecord::AgentLocked(e) => {
            (e.timestamp, e.agent_id.as_deref())
        }
        AuditRecord::PolicyReload(e) => (e.timestamp, None),
    }
}

/// Render a `DecisionCode` to its serialised screaming-snake label.
fn code_label(code: &agent_guard_core::DecisionCode) -> String {
    serde_json::to_string(code)
        .unwrap_or_else(|_| "\"UNKNOWN\"".to_string())
        .trim_matches('"')
        .to_string()
}

/// Print a human-readable evidence summary to stdout.
pub fn print_text(report: &ComplianceReport) {
    println!("=== agent-guard compliance report ===");
    println!("generated:   {}", report.generated_at);
    println!(
        "window:      {}",
        report.window_since.as_deref().unwrap_or("all")
    );
    if let Some(agent) = &report.agent_filter {
        println!("agent:       {agent}");
    }
    match (&report.earliest_event, &report.latest_event) {
        (Some(first), Some(last)) => println!("events span: {first} .. {last}"),
        _ => println!("events span: (none)"),
    }
    println!();
    println!(
        "records:     {} ({} parse error(s))",
        report.records_total, report.parse_errors
    );
    println!(
        "decisions:   {} tool_call · {} allow · {} deny · {} ask",
        report.tool_calls, report.allow, report.deny, report.ask
    );

    print_counts("denials by code", &report.denials_by_code);
    print_counts("denials by tool", &report.denials_by_tool);

    println!();
    println!("content findings: {}", report.content_findings);
    print_counts("  by mode", &report.content_by_mode);
    print_counts("  by label", &report.content_by_label);

    println!();
    println!(
        "executions:  {} started · {} finished · {} sandbox failure(s)",
        report.executions_started, report.executions_finished, report.sandbox_failures
    );
    println!(
        "anomalies:   {} triggered · {} agent lock(s)",
        report.anomalies_triggered, report.agents_locked
    );

    println!();
    println!("policy versions: {}", join_or_dash(&report.policy_versions));
    println!("agents:          {}", join_or_dash(&report.agents));
}

fn print_counts(label: &str, counts: &BTreeMap<String, usize>) {
    if counts.is_empty() {
        return;
    }
    println!("{label}:");
    for (key, n) in counts {
        println!("  {key:<32} {n}");
    }
}

fn join_or_dash(items: &[String]) -> String {
    if items.is_empty() {
        "-".to_string()
    } else {
        items.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal synthetic audit lines. Timestamps are recent so the default
    // (no cutoff) path includes them.
    fn deny_line(tool: &str, code: &str, agent: &str) -> String {
        format!(
            r#"{{"type":"tool_call","timestamp":"2026-05-29T12:00:00Z","request_id":"r","session_id":null,"agent_id":"{agent}","actor":null,"tool":"{tool}","payload_hash":null,"decision":"deny","code":"{code}","message":"x","details":null,"policy_version":"v1","matched_rule":null}}"#
        )
    }

    fn allow_line(tool: &str, agent: &str) -> String {
        format!(
            r#"{{"type":"tool_call","timestamp":"2026-05-29T12:00:00Z","request_id":"r","session_id":null,"agent_id":"{agent}","actor":null,"tool":"{tool}","payload_hash":null,"decision":"allow","code":null,"message":null,"details":null,"policy_version":"v1","matched_rule":null}}"#
        )
    }

    fn content_line(mode: &str, label: &str) -> String {
        format!(
            r#"{{"type":"content_finding","timestamp":"2026-05-29T12:00:00Z","request_id":"r","agent_id":"a","tool":"http_request","mode":"{mode}","labels":["{label}"],"count":1}}"#
        )
    }

    #[test]
    fn counts_decisions_and_groups_denials() {
        let log = [
            allow_line("bash", "a"),
            deny_line("bash", "DESTRUCTIVE_COMMAND", "a"),
            deny_line("http_request", "SENSITIVE_CONTENT_BLOCKED", "a"),
        ]
        .join("\n");

        let report = build_report(&log, None, None, None);

        assert_eq!(report.tool_calls, 3);
        assert_eq!(report.allow, 1);
        assert_eq!(report.deny, 2);
        assert_eq!(report.denials_by_code["DESTRUCTIVE_COMMAND"], 1);
        assert_eq!(report.denials_by_code["SENSITIVE_CONTENT_BLOCKED"], 1);
        assert_eq!(report.denials_by_tool["bash"], 1);
        assert_eq!(report.denials_by_tool["http_request"], 1);
        assert_eq!(report.policy_versions, vec!["v1".to_string()]);
        assert_eq!(report.agents, vec!["a".to_string()]);
    }

    #[test]
    fn summarises_content_findings() {
        let log = [
            content_line("mask", "AWS Access Key"),
            content_line("warn", "Email"),
        ]
        .join("\n");

        let report = build_report(&log, None, None, None);

        assert_eq!(report.content_findings, 2);
        assert_eq!(report.content_by_mode["mask"], 1);
        assert_eq!(report.content_by_mode["warn"], 1);
        assert_eq!(report.content_by_label["AWS Access Key"], 1);
        assert_eq!(report.content_by_label["Email"], 1);
    }

    #[test]
    fn agent_filter_excludes_others() {
        let log = [
            deny_line("bash", "DESTRUCTIVE_COMMAND", "a"),
            deny_line("bash", "DESTRUCTIVE_COMMAND", "b"),
        ]
        .join("\n");

        let report = build_report(&log, None, Some("a"), None);

        assert_eq!(report.deny, 1);
        assert_eq!(report.agents, vec!["a".to_string()]);
    }

    #[test]
    fn malformed_lines_are_counted_not_fatal() {
        let log = [
            allow_line("bash", "a"),
            "{ not json".to_string(),
            String::new(),
        ]
        .join("\n");

        let report = build_report(&log, None, None, None);

        assert_eq!(report.records_total, 1);
        assert_eq!(report.parse_errors, 1);
    }
}
