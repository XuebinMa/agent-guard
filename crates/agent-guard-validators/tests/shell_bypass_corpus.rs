//! Differential oracle for the shell-validation rewrite (P0–P4).
//!
//! The bash gates have been patched roughly fifteen times, each time closing
//! one more way to smuggle a command past a flat, hand-rolled tokenizer. This
//! suite turns that history into a single corpus so the AST front-end can be
//! landed against a fixed, citable target instead of another round of
//! whack-a-mole.
//!
//! Two contracts:
//!
//! * every case WITHOUT `known_gap` is an enforced lock — it must keep
//!   behaving exactly as recorded;
//! * every case WITH `known_gap` is a hole the current implementation still
//!   has. The test asserts the hole still reproduces, so it stays measurable
//!   and cannot be forgotten. Closing one means deleting its marker in the
//!   fixture, which promotes it to an enforced lock.

use std::path::Path;

use agent_guard_validators::bash::{validate_bash_command, PermissionMode, ValidationResult};
use serde::Deserialize;

const CORPUS: &str = include_str!("fixtures/shell_bypass_corpus.json");

#[derive(Deserialize)]
struct Corpus {
    workspace: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    command: String,
    mode: String,
    expect: String,
    origin: String,
    #[serde(default)]
    known_gap: Option<String>,
}

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("shell bypass corpus must parse")
}

fn mode_of(case: &Case) -> PermissionMode {
    match case.mode.as_str() {
        "blocked" => PermissionMode::Blocked,
        "read_only" => PermissionMode::ReadOnly,
        "workspace_write" => PermissionMode::WorkspaceWrite,
        "danger_full_access" => PermissionMode::DangerFullAccess,
        other => panic!("case `{}` has unknown mode `{other}`", case.id),
    }
}

/// Collapse the validator verdict to the vocabulary the fixture speaks.
fn verdict_of(result: &ValidationResult) -> &'static str {
    match result {
        ValidationResult::Allow => "allow",
        ValidationResult::Warn { .. } => "warn",
        ValidationResult::Block { .. } => "block",
    }
}

fn run(case: &Case, workspace: &Path) -> ValidationResult {
    validate_bash_command(&case.command, mode_of(case), workspace, &[])
}

#[test]
fn corpus_locked_cases_hold() {
    let corpus = corpus();
    let workspace = Path::new(&corpus.workspace);
    let mut failures = Vec::new();

    for case in corpus.cases.iter().filter(|c| c.known_gap.is_none()) {
        let result = run(case, workspace);
        let actual = verdict_of(&result);
        if actual != case.expect {
            failures.push(format!(
                "  {id:<40} expected {expect:<5} got {actual:<5} (origin {origin})\n    command: {command:?}\n    result:  {result:?}",
                id = case.id,
                expect = case.expect,
                origin = case.origin,
                command = case.command,
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} locked corpus case(s) regressed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Pins the holes the audit found so they stay visible while the AST front-end
/// is built. When a gap is genuinely closed this test fails, which is the
/// signal to delete its `known_gap` marker and let it become a real lock.
#[test]
fn corpus_known_gaps_still_reproduce() {
    let corpus = corpus();
    let workspace = Path::new(&corpus.workspace);
    let mut unexpectedly_fixed = Vec::new();

    for case in corpus.cases.iter().filter(|c| c.known_gap.is_some()) {
        let result = run(case, workspace);
        if verdict_of(&result) == case.expect {
            unexpectedly_fixed.push(format!("  {} ({})", case.id, case.origin));
        }
    }

    assert!(
        unexpectedly_fixed.is_empty(),
        "{} corpus case(s) marked `known_gap` now behave correctly. Delete their \
         `known_gap` marker in tests/fixtures/shell_bypass_corpus.json so they \
         become enforced locks:\n{}",
        unexpectedly_fixed.len(),
        unexpectedly_fixed.join("\n")
    );
}

/// The corpus is only an oracle if every entry is identifiable and traceable.
#[test]
fn corpus_entries_are_well_formed() {
    let corpus = corpus();
    let mut seen = std::collections::BTreeSet::new();

    for case in &corpus.cases {
        assert!(
            seen.insert((case.id.clone(), case.mode.clone())),
            "duplicate corpus entry: {} in mode {}",
            case.id,
            case.mode
        );
        assert!(!case.origin.is_empty(), "case `{}` has no origin", case.id);
        assert!(
            matches!(case.expect.as_str(), "allow" | "warn" | "block"),
            "case `{}` has unknown expect `{}`",
            case.id,
            case.expect
        );
    }

    assert!(
        Path::new(&corpus.workspace).is_absolute(),
        "corpus workspace root must be absolute, got {:?}",
        corpus.workspace
    );
}
