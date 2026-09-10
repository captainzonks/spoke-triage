// ==============================================================================
// prompt.rs - system + user prompt construction
// ==============================================================================
// Description: Evidence rules carried over verbatim from
//              spoke_log_analysis.sh lines 229-253 (docs/spec.md §7) — do not
//              paraphrase. Also folds in the known-patterns file (if present)
//              as institutional-knowledge context: docs/spec.md §6.1 says to
//              "seed verdict... at first migration", but verdict is keyed by
//              template_hash, which prose guidance can't supply — the file's
//              content here is the actual place that knowledge does
//              something, per §9's own suggestion to bundle it into the
//              cached block. See migrations/0001_initial_schema.sql for the
//              longer version of that reasoning.
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-09
// Version: 0.1.0
// ==============================================================================

use crate::db::PendingTemplate;
use serde_json::json;

/// Verbatim from spoke_log_analysis.sh lines 229-253 / docs/spec.md §7, with
/// the one adaptation the spec calls for: "raw log lines present below" ->
/// "exemplar lines present below", since triage-analyst sends normalized
/// templates + exemplars, not raw Loki output.
const EVIDENCE_RULES: &str = r#"## Evidence Rules (CRITICAL - read before writing any finding)

Every finding must be traceable to exemplar lines present below. Specifically:

- **Quote before claiming.** For any claim of a process signal, crash, shutdown,
  restart, OOM, or worker recycling, the `issue` field must include a verbatim
  fragment (>= 20 chars) from an actual log line that contains one of these
  explicit keywords: `SIGINT`, `SIGTERM`, `SIGKILL`, `SIGSEGV`, `SIGABRT`,
  `Received signal`, `forwarding signal`, `Out of memory`, `oom-killer`,
  `Killed process`, `segfault`, `core dumped`, `panic:`, `Shutting down`,
  `Stopping worker`, or `Worker <id> stopped`. If no such line is present in
  the data below, do not produce the finding.
- **Do NOT infer from PIDs.** PID values are not evidence. High PID
  numbers, sequential PID numbers, or multiple distinct PIDs do NOT
  constitute worker recycling, churn, or signals. Report such things only
  when an explicit signal/shutdown line exists.
- **Framework "signals" != Unix signals.** Log lines mentioning
  Django-style `signals` modules (e.g. `authentik.X.signals`, logger names
  ending in `.signals`, "Imported related module ... signals") are
  framework pub/sub imports. Never report these as SIGINT/SIGTERM/SIGKILL
  events.
- **Timestamps and PIDs must be verbatim.** Every `first_seen`,
  `last_seen`, `count`, and any PID you cite must come from the raw data.
  Do not estimate, interpolate, or synthesize values.
- **Prefer omission over fabrication.** If the data does not clearly
  support a finding, leave it out. An empty section is better than an
  invented one."#;

const TASK_INSTRUCTIONS: &str = r#"You are analyzing server logs for a Spoke infrastructure instance. Below are normalized log templates aggregated from Loki: each one represents one or more structurally-identical raw log lines with variable substrings (timestamps, IPs, UUIDs, etc.) replaced by typed placeholders, plus a count, first/last seen timestamps, and a few verbatim exemplar lines.

## Your Task

1. Review each template below.
2. Classify each one that represents a genuine issue by severity:
   - **CRITICAL**: OOM kills, segfaults, panics, container crashes, data loss, security breaches
   - **HIGH**: Persistent recurring errors, service connectivity failures, auth failures, resource warnings
   - **MEDIUM**: Intermittent errors, non-critical service warnings, configuration issues
   - **LOW**: Transient network hiccups, expected retries, routine warnings
   - **INFO**: Normal operations that matched error patterns but aren't actual problems
3. Templates already flagged `watch` below carry an operator note — read it for context, still classify normally.
4. Ignore noise: health check failures for stopped containers are expected (mention briefly, don't over-report).
5. Context matters: errors from critical infrastructure (traefik, authentik, postgres, crowdsec) rank higher.
6. For CRITICAL/HIGH items, suggest a specific remediation step.
7. Not every template needs a finding — templates that are routine/benign should simply be omitted from findings."#;

pub fn build_system_prompt(known_patterns: Option<&str>) -> String {
    let mut prompt = format!("{TASK_INSTRUCTIONS}\n\n{EVIDENCE_RULES}");
    if let Some(patterns) = known_patterns {
        prompt.push_str("\n\n## Known Patterns (Institutional Knowledge)\n\nThe following patterns have been observed and classified by the operator. Use these to calibrate your severity ratings — do not escalate items that match known-benign patterns.\n\n");
        prompt.push_str(patterns);
    }
    prompt
}

pub fn build_user_message(templates: &[PendingTemplate]) -> String {
    let payload: Vec<_> = templates
        .iter()
        .map(|t| {
            json!({
                "template_hash": t.template_hash,
                "service": t.service_name,
                "logger": t.logger,
                "template": t.template_text,
                "count": t.total_count,
                "first_seen": t.first_seen.to_rfc3339(),
                "last_seen": t.last_seen.to_rfc3339(),
                "exemplar_lines": t.exemplar_lines,
                "verdict": t.verdict_classification,
                "operator_note": t.verdict_note,
            })
        })
        .collect();

    format!(
        "## Log Templates\n\n{}",
        serde_json::to_string_pretty(&payload).unwrap_or_default()
    )
}
