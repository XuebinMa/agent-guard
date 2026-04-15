//! Generates a self-contained HTML security posture report from CapabilityDoctor.
//!
//! Usage: cargo run -p agent-guard-sdk --example dashboard
//! Output: agent-guard-report.html

use agent_guard_sdk::{collect_doctor_report, render_doctor_html};

fn main() {
    let report = collect_doctor_report();
    let html = render_doctor_html(&report);
    let path = "agent-guard-report.html";
    std::fs::write(path, html).unwrap();
    println!("Security posture report written to: {}", path);
}
