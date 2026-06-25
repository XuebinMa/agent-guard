//! Fidelity harness for the `agent-guard-unwrap-v1` normalization annex.
//!
//! The Python `normalize_check.py` is a *second* implementation of the unwrap
//! rules and proves the digest-level properties. This harness proves the other
//! half: that the documented normalization is faithful to the SHIPPED gate, by
//! running agent-guard's real public `validate_bash_command` on each vector and
//! confirming the gate's verdicts agree with the annex's equivalence /
//! fail-closed claims. It uses only the public validator API — no `pub(crate)`
//! access and no change to production code.
//!
//! What the gate can witness (and what it can't): the gate exposes an
//! allow/block verdict, not the raw normalized argv, so equivalence is proven
//! at the verdict level — every wrapped form of a class gets the SAME verdict as
//! the bare canonical command, i.e. the wrappers are transparent to the gate.
//! Exact-digest divergence is left to `normalize_check.py`; the gate's verdict
//! is coarser than the digest (two different `rm` targets both block).

use std::path::Path;

use agent_guard_validators::bash::{validate_bash_command, PermissionMode, ValidationResult};
use serde_json::Value;

fn verdict(cmd: &str, mode: PermissionMode) -> ValidationResult {
    validate_bash_command(cmd, mode, Path::new("/tmp/agent-guard-ws"), &[])
}

fn join(argv: &Value) -> String {
    argv.as_array()
        .expect("argv array")
        .iter()
        .map(|t| t.as_str().expect("argv token is a string"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_block(result: &ValidationResult) -> bool {
    matches!(result, ValidationResult::Block { .. })
}

fn main() {
    let raw = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors.json"))
        .expect("read vectors.json");
    let vectors: Value = serde_json::from_slice(&raw).expect("parse vectors.json");

    let mut ok = true;
    let mut check = |label: &str, cond: bool| {
        ok &= cond;
        println!("[{}] {label}", if cond { "OK" } else { "FAIL" });
    };

    // Equivalence: every wrapped form gets the SAME real-gate verdict as the bare
    // canonical command, and that verdict matches the recorded class expectation.
    for cls in vectors["equivalence_classes"].as_array().unwrap() {
        let name = cls["name"].as_str().unwrap();
        let canonical = join(&cls["canonical_argv"]);
        let canonical_verdict = verdict(&canonical, PermissionMode::ReadOnly);
        let expect_block = cls["gate_read_only"].as_str().unwrap() == "block";
        check(
            &format!(
                "class {name}: canonical `{canonical}` is {}",
                if expect_block { "block" } else { "allow" }
            ),
            is_block(&canonical_verdict) == expect_block,
        );
        for form in cls["forms"].as_array().unwrap() {
            let cmd = join(form);
            check(
                &format!("class {name}: `{cmd}` tracks canonical verdict (wrapper transparent)"),
                verdict(&cmd, PermissionMode::ReadOnly) == canonical_verdict,
            );
        }
    }

    // Fail-closed: a target-hiding spawner (xargs / find -exec) blocks in
    // WorkspaceWrite because the real write target is unverifiable.
    for case in vectors["fail_closed_target_hiding"].as_array().unwrap() {
        let cmd = join(&case["argv"]);
        check(
            &format!("fail-closed WorkspaceWrite: `{cmd}` blocks"),
            is_block(&verdict(&cmd, PermissionMode::WorkspaceWrite)),
        );
    }

    println!(
        "\n{}",
        if ok {
            "gate fidelity confirmed"
        } else {
            "FIDELITY MISMATCH"
        }
    );
    std::process::exit(if ok { 0 } else { 1 });
}
