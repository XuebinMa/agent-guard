//! Where audit lines go.
//!
//! Split out of `guard.rs`. The sink plumbing and the three emitters sit
//! together because they share one rule that is easy to break by editing
//! only one of them: `audit.enabled` gates the whole stream, not the
//! tool-call line alone. A record that reaches only some sinks is the defect
//! that hid every `agent_locked` from file-audited deployments.

use std::sync::Arc;

use agent_guard_core::{AuditEvent, GuardDecision, GuardInput, ReloadEvent};
use agent_guard_validators::bash::GitPushIntent;

use crate::guard::{Guard, GuardState};
use crate::guard_git_preview::{git_push_intent_values, insert_git_push_intents};

/// Destination for non-file audit lines. Defaults to stdout; hosts and
/// tests can redirect it via `Guard::set_audit_sink` so the library never
/// owns the process stdout outright.
pub(crate) type AuditSink = Arc<std::sync::Mutex<Box<dyn std::io::Write + Send>>>;

pub(crate) fn stdout_audit_sink() -> AuditSink {
    Arc::new(std::sync::Mutex::new(Box::new(std::io::stdout())))
}

/// Write one audit line to the sink. An unwritable sink must not panic or
/// abort the decision path; the failure is surfaced via tracing and the
/// SIEM export remains the durable channel.
fn write_to_audit_sink(sink: &AuditSink, line: &str) {
    use std::io::Write;
    match sink.lock() {
        Ok(mut writer) => {
            if let Err(error) = writeln!(writer, "{line}") {
                tracing::error!(%error, "failed to write audit line to sink");
            }
        }
        Err(_) => {
            tracing::error!("audit sink mutex poisoned; audit line dropped from sink output");
        }
    }
}

impl Guard {
    /// Send one record to every configured audit sink.
    ///
    /// `write_audit` gates the tool-call line on `audit_cfg.enabled`; this
    /// does the same for the records that are not tool calls, so enabling or
    /// disabling audit governs the whole stream rather than part of it.
    pub(crate) fn emit_record(&self, state: &GuardState, record: agent_guard_core::AuditRecord) {
        if !state.audit_cfg.enabled {
            return;
        }

        if state.audit_cfg.output == "file" {
            if let Some(ref writer) = state.audit_file_writer {
                let line = serde_json::to_string(&record).unwrap_or_else(|e| {
                    format!("{{\"error\":\"audit serialization failed: {e}\"}}")
                });
                writer.send(line);
            }
        }

        state.siem_exporter.export(record);
    }

    pub(crate) fn write_audit(
        &self,
        input: &GuardInput,
        decision: &GuardDecision,
        git_push_intents: &[GitPushIntent],
        state: &GuardState,
        request_id: &str,
    ) {
        if !state.audit_cfg.enabled {
            return;
        }

        let mut event = AuditEvent::from_decision(
            request_id.to_string(),
            &input.tool,
            &input.payload,
            decision,
            input.context.session_id.clone(),
            input.context.agent_id.clone(),
            input.context.actor.clone(),
            state.audit_cfg.include_payload_hash,
            state.engine.version().to_string(),
        );
        // An Allow decision is intentionally a unit variant, so it cannot
        // carry evaluation metadata itself. Preserve every recognised push
        // proposal in the audit event anyway: the allowed outbound action is
        // the one operators most need to reconstruct later.
        if !git_push_intents.is_empty() {
            let values = git_push_intent_values(git_push_intents, &input.context);
            insert_git_push_intents(&mut event.details, &values);
        }
        let line = event.to_jsonl();

        state
            .siem_exporter
            .export(agent_guard_core::AuditRecord::ToolCall(event));

        if state.audit_cfg.output == "file" {
            if let Some(ref writer) = state.audit_file_writer {
                writer.send(line);
            }
        } else {
            write_to_audit_sink(&state.audit_sink, &line);
        }
    }

    pub(crate) fn write_reload_audit(&self, event: &ReloadEvent, state: &GuardState) {
        let line = event.to_jsonl();
        state
            .siem_exporter
            .export(agent_guard_core::AuditRecord::PolicyReload(event.clone()));

        if state.audit_cfg.enabled && state.audit_cfg.output == "file" {
            if let Some(ref writer) = state.audit_file_writer {
                writer.send(line);
            }
        }
    }
}
