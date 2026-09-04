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

/// One sentence a person can act on, for a permission prompt.
///
/// The full parsed intent goes into the decision's `details`, where a
/// consumer can parse it. It used to be serialized into the prompt as well,
/// which put four hundred characters of JSON in front of a human deciding in
/// a dialog — and anything actionable after it, including where to go
/// instead, arrived past the point where a prompt gets clicked through.
///
/// Two audiences, two renderings, and the machine-readable one is not the one
/// that belongs in the sentence.
fn summarize_intents(intents: &[GitPushIntent]) -> String {
    let Some(first) = intents.first() else {
        // Not reachable through `with_git_push_preview`, which returns early
        // on an empty slice, but a summary that invents a subject would be
        // worse than one that admits it has none.
        return "Approve outbound Git update".to_string();
    };

    let mut sentence = format!("Approve {}", first.command);

    if let Some(remote) = &first.remote {
        sentence.push_str(&format!(" to {remote}"));
    } else {
        // The command names no remote, so git would use its configured
        // default. Saying which one that is would require reading the
        // repository, and guessing it into a prompt is worse than saying it
        // is unstated.
        sentence.push_str(" to the default remote");
    }

    match first.refspecs.as_slice() {
        [] => sentence.push_str(", current branch"),
        [one] => sentence.push_str(&format!(", {one}")),
        many => sentence.push_str(&format!(", {} refspecs", many.len())),
    }

    // The destructive semantics are why a human is being asked at all, so
    // they go in the sentence rather than only in the payload.
    let mut notes: Vec<&str> = Vec::new();
    if first.delete {
        notes.push("removes the remote branch");
    }
    if first.mirror {
        notes.push("mirror: replaces the remote's refs");
    }
    if first.force {
        notes.push("force: may discard commits on the remote");
    } else if first.force_with_lease {
        notes.push("force-with-lease");
    }
    if matches!(first.detection, GitPushDetection::EmbeddedArgv { .. }) {
        notes.push("argv candidate: execution semantics unverified");
    }
    if !notes.is_empty() {
        sentence.push_str(&format!(" — {}", notes.join("; ")));
    }

    if intents.len() > 1 {
        sentence.push_str(&format!(
            " (and {} more outbound update(s); see the audit record)",
            intents.len() - 1
        ));
    }

    sentence
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
            GuardDecision::ask_with_reason(summarize_intents(intents), attach(reason))
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

    /// Build the ask decision the runtime would produce for `command`.
    fn ask_for(command: &str) -> GuardDecision {
        let intents = git_push_intents(command).expect("parses");
        let decision = GuardDecision::ask_with_reason(
            "policy asks",
            agent_guard_core::DecisionReason::new(
                agent_guard_core::DecisionCode::AskRequired,
                "policy asks",
            ),
        );
        with_git_push_preview(decision, &intents, &Context::default())
    }

    /// The prompt, asserted to be prose on the way out.
    ///
    /// The check lives here because the earlier version of these tests passed
    /// against the serialized dump by accident — a JSON blob containing
    /// `"force":true` satisfies a search for "force" while telling a human
    /// nothing. Every prompt assertion is now made about a sentence.
    fn prompt_of(decision: &GuardDecision) -> String {
        let prompt = match decision {
            GuardDecision::AskUser { message, .. } => message.clone(),
            other => panic!("expected an ask, got {other:?}"),
        };
        assert!(
            !prompt.contains('{') && !prompt.contains('['),
            "the prompt must not carry serialized structure: {prompt}"
        );
        prompt
    }

    /// The prompt is read by a person deciding in a permission dialog. A
    /// serialized intent array is not something a person reads, and burying
    /// the actionable part behind it is how a prompt gets clicked through.
    #[test]
    fn the_prompt_is_a_sentence_not_a_json_dump() {
        let prompt = prompt_of(&ask_for("git push origin main"));

        assert!(
            !prompt.contains('{') && !prompt.contains('['),
            "the prompt must not carry serialized structure: {prompt}"
        );
        assert!(
            prompt.len() < 200,
            "a prompt nobody finishes reading is a prompt nobody reads: {} chars",
            prompt.len()
        );
        assert!(prompt.contains("origin"), "{prompt}");
        assert!(prompt.contains("main"), "{prompt}");
    }

    /// Readability must not be bought by dropping evidence. The structured
    /// intent stays where a consumer can parse it.
    #[test]
    fn the_structured_intent_survives_in_the_details() {
        let decision = ask_for("git push origin main");
        let GuardDecision::AskUser { reason, .. } = &decision else {
            panic!("expected an ask");
        };

        let details = reason.details().expect("details present");
        let intents = details
            .get("git_push_intents")
            .and_then(|v| v.as_array())
            .expect("structured intents present");
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0]["remote"], "origin");
        assert_eq!(intents[0]["refspecs"], serde_json::json!(["main"]));
    }

    /// The destructive semantics are the reason a human is being asked at
    /// all, so they belong in the sentence rather than only in the payload.
    #[test]
    fn a_force_push_says_so_in_the_prompt() {
        let prompt = prompt_of(&ask_for("git push --force origin main"));
        assert!(
            prompt.to_lowercase().contains("force"),
            "a force push must be visible in the prompt: {prompt}"
        );
    }

    #[test]
    fn a_branch_removal_says_so_in_the_prompt() {
        let flag = concat!("--", "delete");
        let prompt = prompt_of(&ask_for(&format!("git push origin {flag} main")));
        let lowered = prompt.to_lowercase();
        assert!(
            lowered.contains("remov") || lowered.contains("delet"),
            "a removal must be visible in the prompt: {prompt}"
        );
    }

    /// The conservative-candidate caveat is the whole point of that detection
    /// mode and must survive the rewrite.
    #[test]
    fn an_argv_candidate_keeps_its_unverified_caveat() {
        let prompt = prompt_of(&ask_for("unknown-wrapper git push origin main"));
        assert!(
            prompt.to_lowercase().contains("unverified"),
            "an unverified candidate must still say so: {prompt}"
        );
    }

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
