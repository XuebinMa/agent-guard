use agent_guard_sdk::{collect_doctor_report, render_doctor_text};

fn main() {
    let report = collect_doctor_report();
    println!("{}", render_doctor_text(&report));
}
