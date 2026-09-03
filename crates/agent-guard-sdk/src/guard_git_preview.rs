//! Shaping recognized Git push intent for previews and audit records.
//!
//! Split out of `guard.rs`: the outbound Git surface is the part of the
//! decision path that has to be reconstructable later, so the code that
//! renders an intent into something an operator can read sits together
//! rather than interleaved with policy evaluation.

use std::path::{Path, PathBuf};

use agent_guard_core::{Context, GuardDecision};
use agent_guard_validators::bash::{GitPushDetection, GitPushIntent};

fn git_effective_working_directory(
    context: &Context,
    directory_changes: &[String],
) -> Option<PathBuf> {
    let mut current = context.working_directory.clone();
    for change in directory_changes {
        if change.is_empty() {
            continue;
        }
        let path = Path::new(change);
        current = Some(if path.is_absolute() {
            path.to_path_buf()
        } else if let Some(base) = current {
            base.join(path)
        } else {
            path.to_path_buf()
        });
    }
    current
}

fn resolve_git_selector(base: Option<&Path>, selector: Option<&str>) -> Option<PathBuf> {
    let selector = Path::new(selector?);
    Some(if selector.is_absolute() {
        selector.to_path_buf()
    } else if let Some(base) = base {
        base.join(selector)
    } else {
        selector.to_path_buf()
    })
}

pub(crate) fn git_push_intent_values(
    intents: &[GitPushIntent],
    context: &Context,
) -> Vec<serde_json::Value> {
    intents
        .iter()
        .map(|intent| {
            let effective_directory =
                git_effective_working_directory(context, &intent.directory_changes);
            let effective_git_dir =
                resolve_git_selector(effective_directory.as_deref(), intent.git_dir.as_deref());
            let effective_work_tree =
                resolve_git_selector(effective_directory.as_deref(), intent.work_tree.as_deref());
            let (detection_kind, execution_semantics, outer_command, argument_index) = match &intent
                .detection
            {
                GitPushDetection::ModeledExecution => ("modeled_execution", "modeled", None, None),
                GitPushDetection::EmbeddedArgv {
                    outer_command,
                    argument_index,
                } => (
                    "embedded_argv",
                    "unverified",
                    Some(outer_command.as_str()),
                    Some(*argument_index),
                ),
            };
            serde_json::json!({
                "command": intent.command,
                "detection_kind": detection_kind,
                "execution_semantics": execution_semantics,
                "outer_command": outer_command,
                "argument_index": argument_index,
                "starting_working_directory": context.working_directory,
                "directory_changes": intent.directory_changes,
                "effective_working_directory": effective_directory,
                "git_dir": intent.git_dir,
                "effective_git_dir": effective_git_dir,
                "work_tree": intent.work_tree,
                "effective_work_tree": effective_work_tree,
                "remote": intent.remote,
                "refspecs": intent.refspecs,
                "force": intent.force,
                "force_with_lease": intent.force_with_lease,
                "force_if_includes": intent.force_if_includes,
                "mirror": intent.mirror,
                "delete": intent.delete,
            })
        })
        .collect()
}

pub(crate) fn insert_git_push_intents(
    details: &mut Option<serde_json::Value>,
    intent_values: &[serde_json::Value],
) {
    if intent_values.is_empty() {
        return;
    }
    let mut object = details
        .take()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    object.insert(
        "git_push_intents".to_string(),
        serde_json::Value::Array(intent_values.to_vec()),
    );
    *details = Some(serde_json::Value::Object(object));
}

pub(crate) fn with_git_push_preview(
    decision: GuardDecision,
    intents: &[GitPushIntent],
    context: &Context,
) -> GuardDecision {
    if intents.is_empty() {
        return decision;
    }

    let intent_values = git_push_intent_values(intents, context);

    let attach = |reason: agent_guard_core::DecisionReason| {
        let mut details = reason.details().cloned();
        insert_git_push_intents(&mut details, &intent_values);
        reason.with_details(details.unwrap_or_else(|| serde_json::json!({})))
    };

    match decision {
        GuardDecision::AskUser { reason, .. } => {
            let preview = serde_json::to_string(&intent_values)
                .unwrap_or_else(|_| "[unavailable]".to_string());
            let prompt = if intents
                .iter()
                .any(|intent| matches!(intent.detection, GitPushDetection::EmbeddedArgv { .. }))
            {
                format!(
                    "Git outbound update approval required for a conservative argv candidate whose execution semantics are unverified: {preview}"
                )
            } else {
                format!("Git outbound update approval required for exact parsed intent: {preview}")
            };
            GuardDecision::ask_with_reason(prompt, attach(reason))
        }
        GuardDecision::Deny { reason } => GuardDecision::Deny {
            reason: attach(reason),
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_guard_validators::bash::git_push_intents;
    use std::path::PathBuf;

    #[test]
    fn git_push_preview_keeps_repository_selectors_distinct() {
        let intents =
            git_push_intents("git -C /workspace --git-dir=.git --work-tree=src push origin main")
                .expect("valid push");
        let values = git_push_intent_values(
            &intents,
            &Context {
                working_directory: Some(PathBuf::from("/starting")),
                ..Default::default()
            },
        );
        let preview = &values[0];

        assert_eq!(
            preview["directory_changes"],
            serde_json::json!(["/workspace"])
        );
        assert_eq!(preview["effective_working_directory"], "/workspace");
        assert_eq!(preview["git_dir"], ".git");
        assert_eq!(preview["effective_git_dir"], "/workspace/.git");
        assert_eq!(preview["work_tree"], "src");
        assert_eq!(preview["effective_work_tree"], "/workspace/src");
        assert_eq!(preview["detection_kind"], "modeled_execution");
        assert_eq!(preview["execution_semantics"], "modeled");
        assert!(preview["outer_command"].is_null());
        assert!(preview["argument_index"].is_null());

        let send_pack = git_push_intents("git send-pack origin main").expect("valid send-pack");
        let send_pack_values = git_push_intent_values(&send_pack, &Context::default());
        assert_eq!(send_pack_values[0]["command"], "git send-pack");
    }
}
