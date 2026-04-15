use crate::{
    CapabilityDoctor, DefaultSandboxDiagnosis, Guard, HealthStatus, RuntimeCheckStatus,
    SandboxReport,
};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub generated_at: String,
    pub default_sandbox: DefaultSandboxDiagnosis,
    pub reports: Vec<SandboxReport>,
}

pub fn collect_doctor_report() -> DoctorReport {
    DoctorReport {
        generated_at: chrono::Utc::now()
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string(),
        default_sandbox: Guard::default_sandbox_diagnosis(),
        reports: CapabilityDoctor::report(),
    }
}

pub fn render_doctor_text(report: &DoctorReport) -> String {
    let mut output = String::new();
    output.push_str("agent-guard doctor — Host Capability Report\n\n");
    output.push_str(&format!("Generated: {}\n", report.generated_at));
    output.push_str("Default SDK sandbox:\n");
    output.push_str(&format!(
        "  - Selected: {} ({})\n",
        report.default_sandbox.selected_name, report.default_sandbox.selected_sandbox_type
    ));
    output.push_str(&format!(
        "  - Fallback: {}\n",
        if report.default_sandbox.fallback_to_noop {
            "Yes"
        } else {
            "No"
        }
    ));
    output.push_str(&format!(
        "  - Reason:   {}\n\n",
        report.default_sandbox.reason
    ));

    for item in &report.reports {
        output.push_str("--------------------------------------------------\n");
        output.push_str(&format!("Sandbox: {} ({})\n", item.name, item.sandbox_type));
        output.push_str(&format!(
            "Status:  {}\n",
            if item.is_available {
                "AVAILABLE"
            } else {
                "NOT AVAILABLE"
            }
        ));
        if let Some(note) = &item.availability_note {
            output.push_str(&format!("Note:    {}\n", note));
        }
        let health = match &item.health {
            HealthStatus::Pass => "PASS".to_string(),
            HealthStatus::Fail { error } => format!("FAIL ({error})"),
            HealthStatus::Skipped => "SKIPPED".to_string(),
        };
        output.push_str(&format!("Health:  {}\n", health));
        if !item.runtime_checks.is_empty() {
            output.push_str("Runtime checks:\n");
            for check in &item.runtime_checks {
                let badge = match check.status {
                    RuntimeCheckStatus::Pass => "PASS",
                    RuntimeCheckStatus::Fail => "FAIL",
                    RuntimeCheckStatus::Skipped => "SKIPPED",
                };
                output.push_str(&format!("  - {} {}: {}\n", badge, check.name, check.detail));
            }
        }
        output.push_str("Capabilities:\n");
        output.push_str(&format!(
            "  - FS Workspace Read:  {}\n",
            yes_no(item.capabilities.filesystem_read_workspace)
        ));
        output.push_str(&format!(
            "  - FS Global Read:     {}\n",
            yes_no(item.capabilities.filesystem_read_global)
        ));
        output.push_str(&format!(
            "  - FS Workspace Write: {}\n",
            yes_no(item.capabilities.filesystem_write_workspace)
        ));
        output.push_str(&format!(
            "  - FS Global Write:    {}\n",
            yes_no(item.capabilities.filesystem_write_global)
        ));
        output.push_str(&format!(
            "  - Network Any:        {}\n",
            yes_no(item.capabilities.network_outbound_any)
        ));
        output.push('\n');
    }

    output
}

pub fn render_doctor_html(report: &DoctorReport) -> String {
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "unknown".to_string());
    let json = serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string());

    let mut cards = String::new();
    for item in &report.reports {
        let avail_badge = if item.is_available {
            r#"<span class="badge green">Available</span>"#
        } else {
            r#"<span class="badge red">Not Available</span>"#
        };
        let health_badge = match &item.health {
            HealthStatus::Pass => r#"<span class="badge green">Pass</span>"#.to_string(),
            HealthStatus::Fail { error } => {
                format!(
                    r#"<span class="badge red">Fail: {}</span>"#,
                    escape_html(error)
                )
            }
            HealthStatus::Skipped => r#"<span class="badge gray">Skipped</span>"#.to_string(),
        };
        let note = item
            .availability_note
            .as_ref()
            .map(|value| format!(r#"<p><strong>Note:</strong> {}</p>"#, escape_html(value)))
            .unwrap_or_default();
        let runtime_checks = if item.runtime_checks.is_empty() {
            String::new()
        } else {
            let items = item
                .runtime_checks
                .iter()
                .map(|check| {
                    let badge = match check.status {
                        RuntimeCheckStatus::Pass => "PASS",
                        RuntimeCheckStatus::Fail => "FAIL",
                        RuntimeCheckStatus::Skipped => "SKIPPED",
                    };
                    format!(
                        "<li><strong>{}</strong> [{}] - {}</li>",
                        escape_html(&check.name),
                        badge,
                        escape_html(&check.detail)
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            format!(
                r#"<div class="checks"><strong>Runtime checks</strong><ul>{}</ul></div>"#,
                items
            )
        };

        let capabilities = &item.capabilities;
        cards.push_str(&format!(
            r#"<div class="card">
  <h3>{name} <small>({sandbox_type})</small></h3>
  <p>{avail} {health}</p>
  {note}
  <p><strong>Default Selection:</strong> {selected}</p>
  {runtime_checks}
  <table class="cap-table">
    <tr><td>FS Read (Workspace)</td><td>{fs_rw}</td></tr>
    <tr><td>FS Read (Global)</td><td>{fs_rg}</td></tr>
    <tr><td>FS Write (Workspace)</td><td>{fs_ww}</td></tr>
    <tr><td>FS Write (Global)</td><td>{fs_wg}</td></tr>
    <tr><td>Network Outbound</td><td>{net}</td></tr>
    <tr><td>Child Process</td><td>{proc}</td></tr>
  </table>
</div>
"#,
            name = escape_html(item.name),
            sandbox_type = escape_html(item.sandbox_type),
            avail = avail_badge,
            health = health_badge,
            note = note,
            selected = if item.sandbox_type == report.default_sandbox.selected_sandbox_type {
                "Yes"
            } else {
                "No"
            },
            runtime_checks = runtime_checks,
            fs_rw = cap_icon(capabilities.filesystem_read_workspace, true),
            fs_rg = cap_icon(capabilities.filesystem_read_global, true),
            fs_ww = cap_icon(capabilities.filesystem_write_workspace, true),
            fs_wg = cap_icon(capabilities.filesystem_write_global, false),
            net = cap_icon(capabilities.network_outbound_any, false),
            proc = cap_icon(capabilities.child_process_spawn, true),
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>agent-guard Security Posture Report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; color: #333; padding: 2rem; }}
  h1 {{ color: #1a1a2e; margin-bottom: 0.5rem; }}
  h2 {{ color: #16213e; margin: 2rem 0 1rem; }}
  h3 {{ color: #1a1a2e; margin-bottom: 0.5rem; }}
  .meta {{ color: #666; margin-bottom: 2rem; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1rem; }}
  .card {{ background: #fff; border-radius: 8px; padding: 1.5rem; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.85em; font-weight: 600; }}
  .badge.green {{ background: #d4edda; color: #155724; }}
  .badge.red {{ background: #f8d7da; color: #721c24; }}
  .badge.gray {{ background: #e2e3e5; color: #383d41; }}
  .checks {{ margin: 0.75rem 0 0.25rem; }}
  .checks ul {{ margin: 0.5rem 0 0 1.2rem; }}
  .checks li {{ margin: 0.2rem 0; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th, td {{ border: 1px solid #dee2e6; padding: 8px 12px; text-align: left; }}
  th {{ background: #e9ecef; font-weight: 600; }}
  .cap-table td:last-child {{ text-align: center; }}
  pre {{ background: #1a1a2e; color: #a0ffa0; padding: 1rem; border-radius: 8px; overflow-x: auto; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>agent-guard Security Posture Report</h1>
<p class="meta">Generated: {generated_at} | Host: {hostname}</p>

<h2>Default Sandbox Resolution</h2>
<div class="card">
  <h3>{default_name} <small>({default_type})</small></h3>
  <p>{default_badge}</p>
  <p><strong>Reason:</strong> {default_reason}</p>
</div>

<h2>Sandbox Overview</h2>
<div class="cards">
{cards}
</div>

<h2>Raw Data (JSON)</h2>
<pre>{json}</pre>
</body>
</html>"#,
        generated_at = escape_html(&report.generated_at),
        hostname = escape_html(&hostname),
        default_name = escape_html(report.default_sandbox.selected_name),
        default_type = escape_html(report.default_sandbox.selected_sandbox_type),
        default_badge = if report.default_sandbox.fallback_to_noop {
            r#"<span class="badge red">Fallback to NoopSandbox</span>"#
        } else {
            r#"<span class="badge green">Native backend selected</span>"#
        },
        default_reason = escape_html(&report.default_sandbox.reason),
        cards = cards,
        json = escape_html(&json),
    )
}

fn cap_icon(value: bool, positive_means_good: bool) -> &'static str {
    if positive_means_good {
        if value {
            "Yes"
        } else {
            "No"
        }
    } else if value {
        "Allowed"
    } else {
        "Blocked"
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "Yes"
    } else {
        "No"
    }
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::{collect_doctor_report, render_doctor_html, render_doctor_text};

    #[test]
    fn doctor_renderers_include_expected_sections() {
        let report = collect_doctor_report();
        let text = render_doctor_text(&report);
        let html = render_doctor_html(&report);

        assert!(text.contains("Host Capability Report"));
        assert!(text.contains("Default SDK sandbox"));
        assert!(html.contains("<html"));
        assert!(html.contains("Security Posture Report"));
    }
}
