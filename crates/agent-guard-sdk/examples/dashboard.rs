//! Generates a self-contained HTML security posture report from CapabilityDoctor.
//!
//! Usage: cargo run -p agent-guard-sdk --example dashboard
//! Output: agent-guard-report.html

use agent_guard_sdk::{CapabilityDoctor, HealthStatus, SandboxReport};

fn main() {
    let reports = CapabilityDoctor::report();
    let json = serde_json::to_string_pretty(&reports).unwrap();
    let html = render_html(&reports, &json);
    let path = "agent-guard-report.html";
    std::fs::write(path, &html).unwrap();
    println!("Security posture report written to: {}", path);
}

fn render_html(reports: &[SandboxReport], json: &str) -> String {
    let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "unknown".to_string());

    let mut cards = String::new();
    for r in reports {
        let avail_badge = if r.is_available {
            r#"<span class="badge green">Available</span>"#
        } else {
            r#"<span class="badge red">Not Available</span>"#
        };
        let health_badge = match &r.health {
            HealthStatus::Pass => r#"<span class="badge green">Pass</span>"#.to_string(),
            HealthStatus::Fail { error } => {
                format!(r#"<span class="badge red">Fail: {}</span>"#, error)
            }
            HealthStatus::Skipped => r#"<span class="badge gray">Skipped</span>"#.to_string(),
        };

        let cap = &r.capabilities;
        cards.push_str(&format!(
            r#"<div class="card">
  <h3>{name} <small>({stype})</small></h3>
  <p>{avail} {health}</p>
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
            name = r.name,
            stype = r.sandbox_type,
            avail = avail_badge,
            health = health_badge,
            fs_rw = cap_icon(cap.filesystem_read_workspace, true),
            fs_rg = cap_icon(cap.filesystem_read_global, true),
            fs_ww = cap_icon(cap.filesystem_write_workspace, true),
            fs_wg = cap_icon(cap.filesystem_write_global, false),
            net = cap_icon(cap.network_outbound_any, false),
            proc = cap_icon(cap.child_process_spawn, true),
        ));
    }

    // Capability matrix table
    let cap_names = [
        "FS Read (Workspace)",
        "FS Read (Global)",
        "FS Write (Workspace)",
        "FS Write (Global)",
        "Network Outbound (Any)",
        "Network Outbound (Internet)",
        "Network Outbound (Local)",
        "Child Process Spawn",
        "Registry Write",
    ];
    let mut headers = String::new();
    for r in reports {
        headers.push_str(&format!("<th>{}</th>", r.name));
    }
    let mut rows = String::new();
    for (i, name) in cap_names.iter().enumerate() {
        rows.push_str(&format!("<tr><td>{}</td>", name));
        for r in reports {
            let c = &r.capabilities;
            let val = match i {
                0 => c.filesystem_read_workspace,
                1 => c.filesystem_read_global,
                2 => c.filesystem_write_workspace,
                3 => c.filesystem_write_global,
                4 => c.network_outbound_any,
                5 => c.network_outbound_internet,
                6 => c.network_outbound_local,
                7 => c.child_process_spawn,
                8 => c.registry_write,
                _ => false,
            };
            // For "restriction" capabilities (global write, network), inverted meaning
            let is_restriction = i >= 3 && i <= 6;
            rows.push_str(&format!("<td>{}</td>", cap_icon(val, !is_restriction)));
        }
        rows.push_str("</tr>\n");
    }

    format!(
        r##"<!DOCTYPE html>
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
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th, td {{ border: 1px solid #dee2e6; padding: 8px 12px; text-align: left; }}
  th {{ background: #e9ecef; font-weight: 600; }}
  .cap-table td:last-child {{ text-align: center; }}
  .matrix {{ background: #fff; border-radius: 8px; padding: 1.5rem; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow-x: auto; }}
  .matrix th {{ text-align: center; }}
  .matrix td:not(:first-child) {{ text-align: center; }}
  pre {{ background: #1a1a2e; color: #a0ffa0; padding: 1rem; border-radius: 8px; overflow-x: auto; font-size: 0.85em; }}
  footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #dee2e6; color: #888; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>agent-guard Security Posture Report</h1>
<p class="meta">Generated: {timestamp} | Host: {hostname}</p>

<h2>Sandbox Overview</h2>
<div class="cards">
{cards}
</div>

<h2>Capability Matrix (UCM)</h2>
<div class="matrix">
<table>
<thead><tr><th>Capability</th>{headers}</tr></thead>
<tbody>
{rows}
</tbody>
</table>
</div>

<h2>Raw Data (JSON)</h2>
<pre>{json}</pre>

<footer>
<p>Generated by agent-guard CapabilityDoctor v0.2.0-rc1</p>
<p>See <a href="https://github.com/XuebinMa/agent-guard">agent-guard</a> for documentation.</p>
</footer>
</body>
</html>"##,
        timestamp = timestamp,
        hostname = hostname,
        cards = cards,
        headers = headers,
        rows = rows,
        json = json,
    )
}

fn cap_icon(value: bool, positive_means_good: bool) -> &'static str {
    if positive_means_good {
        if value { "&#9989;" } else { "&#10060;" }
    } else {
        // For restriction capabilities: false = blocked = good
        if value { "&#9888;&#65039; Allowed" } else { "&#9989; Blocked" }
    }
}
