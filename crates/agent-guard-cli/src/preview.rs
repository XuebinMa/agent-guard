//! Showing a human what a push would do, and asking them.
//!
//! Every preview used to render as the same block of text with different
//! values in it, so a routine fast-forward and a push that discards remote
//! history were the same shape to a skimming eye. Anthropic's own telemetry
//! puts approval at roughly 93% of prompts, and a study where the malicious
//! command was printed directly above the prompt still had two thirds of
//! readers approve it — so more text on the screen is not the fix, and this
//! module does not try to be one.
//!
//! What it does instead is borrowed from two fields that solved the same
//! problem. Pharmacy stopped look-alike drug names causing wrong doses by
//! making the *difference* salient rather than the label longer. Surgery
//! stopped wrong-site operations with a time-out in which someone reads the
//! site back, because reading a warning and reproducing its subject are
//! different acts and only the second is evidence the reader took it in.
//!
//! So a push with a consequence leads with the consequence instead of burying
//! it in a line of equal weight. Nothing here has been shown to work — it is a
//! design borrowed from places where it did, and the honest status is untested.
//!
//! The surgical half is deliberately absent. A read-back was written and
//! removed: every shape that raises a consequence is one `execute_push`
//! refuses, so it only ever asked a human to type a branch name in front of a
//! wall. It is worth revisiting if the broker's executable set ever grows to
//! include a shape worth pausing over.

use std::io::{self, Write};
use std::path::Path;

use agent_guard_broker::{PushTransaction, RefUpdateKind};

/// What this push would do that a reader must not skim past.
///
/// Only what the resolved transaction *establishes* qualifies. A count of
/// commits deliberately does not: without knowing what the human expected, a
/// large number is not a surprise, and a marker that fires on volume is one
/// people learn to dismiss — which is the failure this exists to avoid.
fn consequence(tx: &PushTransaction) -> Option<&'static str> {
    match tx.kind {
        RefUpdateKind::NotFastForward => {
            Some("This would discard commits the remote has. They are not in your branch.")
        }
        RefUpdateKind::Undetermined => Some(
            "What this would do could not be determined: the remote holds objects \
             this repository has not fetched.",
        ),
        RefUpdateKind::Create | RefUpdateKind::FastForward | RefUpdateKind::UpToDate => None,
    }
}

fn remote_line(tx: &PushTransaction) -> String {
    format!("remote:  {} ({})", tx.remote, tx.remote_url)
}

/// Print the resolved effect, consequence first when there is one.
pub(crate) fn print_preview(tx: &PushTransaction, policy_path: &Path) {
    // Before the details, not after them. A line that explains what is about
    // to be lost is only useful above the block a reader skims.
    if let Some(consequence) = consequence(tx) {
        println!("!! {consequence}");
        println!();
    }

    // Named, even when it was not asked for. Approving a push means approving
    // it under some set of rules, and a default that goes unstated is a rule
    // set the person deciding never saw.
    println!("policy:  {}", policy_path.display());
    println!("{}", remote_line(tx));
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

/// Ask.
pub(crate) fn confirm() -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use agent_guard_broker::{PushTransaction, RefUpdateKind};

    /// A transaction of the given shape. Only `kind` and `added_commits` are
    /// interesting here; the rest is scenery.
    fn transaction(kind: RefUpdateKind, added: Option<Vec<String>>) -> PushTransaction {
        PushTransaction {
            remote: "origin".to_string(),
            remote_url: "git@example.invalid:you/project.git".to_string(),
            branch: "main".to_string(),
            local_oid: "1111111111111111111111111111111111111111".to_string(),
            remote_oid: Some("2222222222222222222222222222222222222222".to_string()),
            kind,
            added_commits: added,
        }
    }

    fn commits(n: usize) -> Option<Vec<String>> {
        Some((0..n).map(|i| format!("{i:040}")).collect())
    }

    // --- nothing to surface -------------------------------------------------

    #[test]
    fn a_fast_forward_surfaces_no_consequence() {
        assert_eq!(
            consequence(&transaction(RefUpdateKind::FastForward, commits(2))),
            None
        );
    }

    #[test]
    fn creating_a_branch_surfaces_no_consequence() {
        assert_eq!(
            consequence(&transaction(RefUpdateKind::Create, commits(2))),
            None
        );
    }

    #[test]
    fn an_up_to_date_push_surfaces_no_consequence() {
        assert_eq!(
            consequence(&transaction(RefUpdateKind::UpToDate, Some(Vec::new()))),
            None
        );
    }

    #[test]
    fn preview_names_the_resolved_push_url_not_only_the_remote_alias() {
        let mut tx = transaction(RefUpdateKind::FastForward, commits(2));
        tx.remote_url = "ssh://push.example.invalid/approved.git".to_string();

        assert_eq!(
            remote_line(&tx),
            "remote:  origin (ssh://push.example.invalid/approved.git)"
        );
    }

    /// The decision this pins is a decision *not* to fire.
    ///
    /// A large push is not a surprising one: without knowing what the human
    /// expected, a count says nothing, and a marker that fires on volume is
    /// one people learn to dismiss — which is the failure this whole thing
    /// exists to avoid.
    #[test]
    fn a_large_but_ordinary_push_is_still_ordinary() {
        let big = transaction(RefUpdateKind::FastForward, commits(200));
        assert_eq!(consequence(&big), None);
    }

    // --- something to surface -----------------------------------------------

    #[test]
    fn discarding_history_is_surfaced() {
        let surfaced = consequence(&transaction(RefUpdateKind::NotFastForward, commits(1)))
            .expect("a non-fast-forward has a consequence");
        assert!(
            surfaced.to_lowercase().contains("discard"),
            "the consequence must name what is lost: {surfaced}"
        );
    }

    #[test]
    fn an_update_that_could_not_be_determined_is_surfaced() {
        let surfaced = consequence(&transaction(RefUpdateKind::Undetermined, None))
            .expect("an undetermined update has a consequence");
        assert!(
            !surfaced.is_empty(),
            "not knowing what a push would do is itself the thing to say"
        );
    }
}
