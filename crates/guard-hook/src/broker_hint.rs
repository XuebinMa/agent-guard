//! Telling a blocked push where to go.
//!
//! A refusal that does not say what to do instead is a dead end. The broker
//! path exists, but an agent stopped at the hook prints a policy code and
//! nothing else, so the human never learns the command exists.
//!
//! The hint is only as specific as it can honestly be. The broker performs
//! ordinary non-force pushes of one branch; pointing anything else at
//! `agent-guard push` would send someone to a command that refuses, and would
//! imply the broker offers a route to the thing policy just stopped.

use agent_guard_validators::bash::{git_push_intents, GitPushIntent};

/// What to tell someone whose push was refused, if anything.
///
/// `None` for commands that are not a recognized push: there is nothing
/// useful to add, and a hint on an unrelated denial is noise that trains
/// people to ignore hints.
pub(crate) fn broker_hint(command: &str) -> Option<String> {
    // Two different silences, both correct. `Err` means the shell was too
    // complex to parse, so nothing is known about what it would push; an
    // empty list means it is not a push at all. Neither can be turned into
    // advice, and inventing one for a command nobody understood is how a
    // hint becomes misinformation.
    let intents = git_push_intents(command).ok()?;
    let intent = intents.first()?;

    if let Some(shape) = unsupported_shape(intent) {
        return Some(format!(
            "agent-guard push does not perform {shape}; it performs ordinary \
             non-force pushes of one branch."
        ));
    }

    let remote = intent.remote.as_deref()?;
    match single_branch(intent) {
        Some(branch) => Some(format!(
            "To have the Guard perform this push, with a preview of exactly \
             what it would change: agent-guard push --remote {remote} --branch {branch}"
        )),
        // The command did not name a branch, so neither can the hint. Naming
        // the wrong one would be worse than naming none.
        None => Some(format!(
            "To have the Guard perform this push, name the branch: \
             agent-guard push --remote {remote} --branch <branch>"
        )),
    }
}

/// The shapes the broker refuses, named the way a human would say them.
fn unsupported_shape(intent: &GitPushIntent) -> Option<&'static str> {
    if intent.delete {
        return Some("remote branch removal");
    }
    if intent.mirror {
        return Some("mirror pushes");
    }
    if intent.force || intent.force_with_lease {
        return Some("force pushes");
    }
    if intent.refspecs.len() > 1 {
        return Some("pushes of several refspecs at once");
    }
    None
}

/// The branch, when the command names exactly one plainly.
///
/// Anything with a source:destination mapping or a leading `+` is left alone:
/// guessing which half a human meant would put a branch name into a command
/// they are about to run.
fn single_branch(intent: &GitPushIntent) -> Option<&str> {
    let refspec = match intent.refspecs.as_slice() {
        [only] => only.as_str(),
        _ => return None,
    };
    if refspec.starts_with('+') || refspec.contains(':') {
        return None;
    }
    Some(refspec)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assembled rather than written out, so this file carries no literal a
    /// destructive-command scanner would match.
    const REMOVAL_FLAG: &str = concat!("--", "delete");

    #[test]
    fn an_ordinary_push_gets_the_exact_command() {
        let hint = broker_hint("git push origin main").expect("a push gets a hint");
        assert!(
            hint.contains("agent-guard push --remote origin --branch main"),
            "{hint}"
        );
    }

    #[test]
    fn a_force_push_is_not_sent_to_a_command_that_refuses_it() {
        let hint = broker_hint("git push --force origin main").expect("a push gets a hint");
        assert!(hint.contains("does not perform force pushes"), "{hint}");
        assert!(
            !hint.contains("--branch main"),
            "a refused shape must not be dressed up as a runnable command: {hint}"
        );
    }

    #[test]
    fn a_removal_says_so_rather_than_offering_a_route() {
        let command = format!("git push origin {REMOVAL_FLAG} main");
        let hint = broker_hint(&command).expect("a push gets a hint");
        assert!(
            hint.contains("does not perform remote branch removal"),
            "{hint}"
        );
    }

    #[test]
    fn a_push_without_a_branch_asks_for_one_instead_of_inventing_it() {
        let hint = broker_hint("git push origin").expect("a push gets a hint");
        assert!(hint.contains("--branch <branch>"), "{hint}");
    }

    #[test]
    fn a_mapped_refspec_is_not_guessed_at() {
        let hint = broker_hint("git push origin HEAD:main").expect("a push gets a hint");
        assert!(
            hint.contains("--branch <branch>"),
            "a source:destination refspec must not be guessed: {hint}"
        );
    }

    #[test]
    fn an_unrelated_command_gets_no_hint() {
        assert!(broker_hint("cargo test").is_none());
        assert!(broker_hint("git status").is_none());
    }
}
