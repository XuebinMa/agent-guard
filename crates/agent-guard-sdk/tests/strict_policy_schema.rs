//! End-to-end regressions for the policy schema authorization boundary.
//!
//! A misspelled protection must fail during Guard construction or reload; it
//! must never become a weaker live policy merely because Serde ignored a key.

use agent_guard_sdk::{Context, Guard, GuardDecision, Tool};

const VALID_DENY_POLICY: &str = r#"
version: 1
default_mode: full_access
tools:
  bash:
    deny:
      - prefix: "danger"
audit:
  enabled: false
anomaly:
  enabled: false
"#;

fn danger_decision(guard: &Guard) -> GuardDecision {
    guard.check_tool(Tool::Bash, r#"{"command":"danger"}"#, Context::default())
}

#[test]
fn misspelled_protections_cannot_construct_a_guard() {
    for yaml in [
        "version: 1\ndenny: true\n",
        "version: 1\ntools:\n  baash:\n    deny: ['danger']\n",
        "version: 1\ntools:\n  bash:\n    deny:\n      - prefx: danger\n",
    ] {
        assert!(
            Guard::from_yaml(yaml).is_err(),
            "misspelled protection unexpectedly constructed a Guard:\n{yaml}"
        );
    }
}

#[test]
fn rejected_misspelled_reload_preserves_the_previous_stronger_policy() {
    let guard = Guard::from_yaml(VALID_DENY_POLICY).expect("valid deny policy");
    let version_before = guard.policy_version();
    assert!(matches!(
        danger_decision(&guard),
        GuardDecision::Deny { .. }
    ));

    let misspelled = VALID_DENY_POLICY.replace("deny:", "denny:");
    assert!(guard.reload_from_yaml(&misspelled).is_err());

    assert_eq!(guard.policy_version(), version_before);
    assert!(
        matches!(danger_decision(&guard), GuardDecision::Deny { .. }),
        "a failed reload must leave the previous deny policy active"
    );
}
