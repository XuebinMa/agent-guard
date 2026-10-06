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

/// Rules for a custom tool are looked up by its id. A section that can never
/// be looked up, or that silently replaces an earlier one, is a protection its
/// author believes in and the Guard never applies.
#[test]
fn custom_tool_sections_that_can_never_apply_cannot_construct_a_guard() {
    for (yaml, names) in [
        (
            // The second mapping would replace the first and drop its rule.
            "version: 1\ntools:\n  custom:\n    acme.sql:\n      deny:\n        - plain: \"drop\"\n    acme.sql: {}\n",
            "acme.sql",
        ),
        (
            // `bash` is governed by `tools.bash`; no custom tool can have this id.
            "version: 1\ntools:\n  custom:\n    bash:\n      deny:\n        - plain: \"danger\"\n",
            "bash",
        ),
        (
            "version: 1\ntools:\n  custom:\n    Write_File:\n      deny:\n        - plain: \"danger\"\n",
            "Write_File",
        ),
        (
            // Not an id any custom tool can carry.
            "version: 1\ntools:\n  custom:\n    \"acme sql\":\n      deny:\n        - plain: \"danger\"\n",
            "acme sql",
        ),
    ] {
        let error = match Guard::from_yaml(yaml) {
            Ok(_) => panic!("a custom section that never applies constructed a Guard:\n{yaml}"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(names), "the error must name the section: {error}");
    }

    let guard = Guard::from_yaml(
        "version: 1\ndefault_mode: full_access\ntools:\n  custom:\n    acme.sql.query:\n      deny:\n        - plain: \"drop\"\n    acme.sql.admin: {}\naudit:\n  enabled: false\nanomaly:\n  enabled: false\n",
    )
    .expect("distinct, valid custom tool ids load");
    let tool = Tool::Custom(agent_guard_sdk::CustomToolId::new("acme.sql.query").expect("id"));
    assert!(matches!(
        guard.check_tool(tool, "drop", Context::default()),
        GuardDecision::Deny { .. }
    ));
}
