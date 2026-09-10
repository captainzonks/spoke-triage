// ==============================================================================
// report_render.rs - HTML/text report rendering for the mail relay
// ==============================================================================
// Description: Preserves spoke_log_analysis.sh's HTML report structure
//              (severity-colored sections, CRITICAL/HIGH as cards, MEDIUM as
//              a bullet list, LOW/INFO condensed) and adds the two signals
//              spec §10 calls for beyond the original: each finding's
//              new/recurring/escalating status (finding.status) and a cost
//              line (from api_call). Pure functions — no I/O — so rendering
//              is unit-testable without a live mail relay.
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-10
// Version: 0.1.1
// ==============================================================================

use crate::db::WrittenFinding;
use chrono::{DateTime, Utc};
use std::fmt::Write as _;

pub struct ReportContext<'a> {
    pub instance_name: &'a str,
    pub lookback_hours: i64,
    pub health: &'a str,
    pub total_events: i64,
    pub summary: &'a str,
    pub findings: &'a [WrittenFinding],
    pub model: &'a str,
    pub run_cost_usd: f64,
    pub month_to_date_usd: f64,
    pub monthly_budget_usd: f64,
    pub generated_at: DateTime<Utc>,
}

const SEVERITY_ORDER: [&str; 5] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

fn health_color(health: &str) -> &'static str {
    match health {
        "healthy" => "#28a745",
        "degraded" => "#fd7e14",
        "critical" => "#dc3545",
        _ => "#6c757d",
    }
}

fn severity_color(severity: &str) -> &'static str {
    match severity {
        "CRITICAL" => "#dc3545",
        "HIGH" => "#fd7e14",
        "MEDIUM" => "#ffc107",
        "LOW" => "#17a2b8",
        _ => "#6c757d",
    }
}

fn group_by_severity(findings: &[WrittenFinding]) -> Vec<(&'static str, Vec<&WrittenFinding>)> {
    SEVERITY_ORDER
        .iter()
        .map(|&sev| (sev, findings.iter().filter(|f| f.severity == sev).collect::<Vec<_>>()))
        .collect()
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

pub fn build_html(ctx: &ReportContext) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        r#"<div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px;">
<h1 style="border-bottom: 3px solid #333; padding-bottom: 10px;">{instance} Daily Log Report</h1>
<p><strong>Period:</strong> Last {lookback} hours |
<strong>Health:</strong> <span style="color: {health_color}; font-weight: bold;">{health}</span> |
<strong>Total Events:</strong> {events}</p>

<h2>Executive Summary</h2>
<p>{summary}</p>"#,
        instance = escape_html(ctx.instance_name),
        lookback = ctx.lookback_hours,
        health_color = health_color(ctx.health),
        health = escape_html(&ctx.health.to_uppercase()),
        events = ctx.total_events,
        summary = escape_html(ctx.summary),
    );

    for (severity, items) in group_by_severity(ctx.findings) {
        let color = severity_color(severity);
        let _ = write!(out, r#"<h2 style="color: {color};">{severity} ({count})</h2>"#, count = items.len());

        if items.is_empty() {
            out.push_str(r#"<p style="color: #999;">None</p>"#);
            continue;
        }

        if matches!(severity, "CRITICAL" | "HIGH") {
            for f in &items {
                let _ = write!(
                    out,
                    r#"<div style="border-left: 4px solid {color}; padding: 8px 12px; margin: 8px 0; background: #f8f9fa;">
<strong>[{status}]</strong> {issue}
{rec}
</div>"#,
                    status = f.status.to_uppercase(),
                    issue = escape_html(&f.issue),
                    rec = f
                        .recommendation
                        .as_deref()
                        .filter(|r| !r.is_empty())
                        .map(|r| format!(r#"<br><em style="color: #0066cc;">Recommendation: {}</em>"#, escape_html(r)))
                        .unwrap_or_default(),
                );
            }
        } else if severity == "MEDIUM" {
            out.push_str("<ul>");
            for f in &items {
                let _ = write!(out, "<li><strong>[{}]</strong> {}</li>", f.status.to_uppercase(), escape_html(&f.issue));
            }
            out.push_str("</ul>");
        } else {
            let shown: Vec<String> = items.iter().take(10).map(|f| escape_html(&f.issue)).collect();
            let _ = write!(out, "<p>{}</p>", shown.join(", "));
            if items.len() > 10 {
                let _ = write!(out, r#"<p style="color: #999;">...and {} more</p>"#, items.len() - 10);
            }
        }
    }

    let _ = write!(
        out,
        r#"<hr style="margin-top: 30px;">
<p style="color: #999; font-size: 0.85em;">Cost: this run ${run_cost:.4} | month-to-date ${mtd:.2} / ${budget:.2} budget</p>
<p style="color: #999; font-size: 0.85em;">Generated by spoke-triage ({model}) at {now}</p>
</div>"#,
        run_cost = ctx.run_cost_usd,
        mtd = ctx.month_to_date_usd,
        budget = ctx.monthly_budget_usd,
        model = escape_html(ctx.model),
        now = ctx.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    out
}

pub fn build_text(ctx: &ReportContext) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{} Daily Log Report", ctx.instance_name);
    let _ = writeln!(out, "{}", "=".repeat(60));
    let _ = writeln!(out, "Period: Last {} hours", ctx.lookback_hours);
    let _ = writeln!(out, "Health: {}", ctx.health.to_uppercase());
    let _ = writeln!(out, "Total Events: {}", ctx.total_events);
    out.push('\n');
    let _ = writeln!(out, "EXECUTIVE SUMMARY");
    let _ = writeln!(out, "{}", "-".repeat(40));
    let _ = writeln!(out, "{}", ctx.summary);
    out.push('\n');

    for (severity, items) in group_by_severity(ctx.findings) {
        let _ = writeln!(out, "{} ({})", severity, items.len());
        let _ = writeln!(out, "{}", "-".repeat(40));
        if items.is_empty() {
            let _ = writeln!(out, "  None");
        } else {
            for f in &items {
                let _ = writeln!(out, "  [{}] {}", f.status.to_uppercase(), f.issue);
                if matches!(severity, "CRITICAL" | "HIGH")
                    && let Some(rec) = f.recommendation.as_deref().filter(|r| !r.is_empty())
                {
                    let _ = writeln!(out, "    -> {rec}");
                }
            }
        }
        out.push('\n');
    }

    let _ = writeln!(out, "---");
    let _ = writeln!(
        out,
        "Cost: this run ${:.4} | month-to-date ${:.2} / ${:.2} budget",
        ctx.run_cost_usd, ctx.month_to_date_usd, ctx.monthly_budget_usd
    );
    let _ = writeln!(out, "Generated by spoke-triage ({})", ctx.model);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(findings: &'a [WrittenFinding]) -> ReportContext<'a> {
        ReportContext {
            instance_name: "spoke",
            lookback_hours: 24,
            health: "degraded",
            total_events: 42,
            summary: "one recurring worker exit",
            findings,
            model: "claude-haiku-4-5",
            run_cost_usd: 0.0123,
            month_to_date_usd: 1.5,
            monthly_budget_usd: 20.0,
            generated_at: DateTime::parse_from_rfc3339("2026-09-09T12:00:00Z").unwrap().with_timezone(&Utc),
        }
    }

    #[test]
    fn html_includes_status_badge_and_cost_line() {
        let findings = vec![WrittenFinding {
            severity: "HIGH".to_string(),
            issue: "worker exited".to_string(),
            recommendation: Some("restart the service".to_string()),
            status: "recurring",
        }];
        let html = build_html(&ctx(&findings));
        assert!(html.contains("[RECURRING]"));
        assert!(html.contains("worker exited"));
        assert!(html.contains("restart the service"));
        assert!(html.contains("this run $0.0123"));
        assert!(html.contains("month-to-date $1.50"));
    }

    #[test]
    fn html_escapes_finding_text() {
        let findings = vec![WrittenFinding {
            severity: "MEDIUM".to_string(),
            issue: "<script>alert(1)</script>".to_string(),
            recommendation: None,
            status: "new",
        }];
        let html = build_html(&ctx(&findings));
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn empty_severity_section_renders_none() {
        let html = build_html(&ctx(&[]));
        assert!(html.contains("CRITICAL (0)"));
        assert!(html.contains("None"));
    }

    #[test]
    fn text_report_includes_status_and_cost() {
        let findings = vec![WrittenFinding {
            severity: "LOW".to_string(),
            issue: "reconnect".to_string(),
            recommendation: None,
            status: "new",
        }];
        let text = build_text(&ctx(&findings));
        assert!(text.contains("[NEW] reconnect"));
        assert!(text.contains("this run $0.0123"));
    }
}
