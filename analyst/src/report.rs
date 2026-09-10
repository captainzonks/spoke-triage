// ==============================================================================
// report.rs - parse the model's triage_report tool call
// ==============================================================================
// Description: Extracts and validates the forced tool_use block. strict:true
//              (spec §5) means the API validates input server-side, but this
//              still checks for the block's presence and required fields
//              defensively rather than assuming the wire never misbehaves.
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-09
// Version: 0.1.0
// ==============================================================================

use crate::anthropic::{ContentBlock, MessagesResponse};
use crate::db::ScoredFinding;
use crate::schema::TRIAGE_REPORT_TOOL_NAME;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Report {
    pub summary: String,
    pub total_events: i64,
    pub health: String,
    pub findings: Vec<RawFinding>,
}

#[derive(Debug, Deserialize)]
pub struct RawFinding {
    pub template_hash: String,
    pub severity: String,
    #[allow(dead_code)]
    pub service: String,
    pub issue: String,
    #[allow(dead_code)]
    pub count: i64,
    #[allow(dead_code)]
    pub first_seen: String,
    #[allow(dead_code)]
    pub last_seen: String,
    pub recommendation: Option<String>,
}

pub fn parse_report(response: &MessagesResponse) -> anyhow::Result<Report> {
    let input = response
        .content
        .iter()
        .find_map(|b| match b {
            ContentBlock::ToolUse { name, input } if name == TRIAGE_REPORT_TOOL_NAME => Some(input),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("no {TRIAGE_REPORT_TOOL_NAME} tool_use block in response"))?;

    Ok(serde_json::from_value(input.clone())?)
}

impl Report {
    pub fn into_scored_findings(self) -> Vec<ScoredFinding> {
        self.findings
            .into_iter()
            .map(|f| ScoredFinding {
                template_hash: f.template_hash,
                severity: f.severity,
                issue: f.issue,
                recommendation: f.recommendation,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::Usage;
    use serde_json::json;

    #[test]
    fn parses_valid_tool_use_response() {
        let response = MessagesResponse {
            content: vec![ContentBlock::ToolUse {
                name: TRIAGE_REPORT_TOOL_NAME.to_string(),
                input: json!({
                    "summary": "one degraded service",
                    "total_events": 42,
                    "health": "degraded",
                    "findings": [{
                        "template_hash": "a".repeat(64),
                        "severity": "HIGH",
                        "service": "plex",
                        "issue": "worker exited",
                        "count": 5,
                        "first_seen": "2026-09-09T00:00:00Z",
                        "last_seen": "2026-09-09T01:00:00Z",
                        "recommendation": "restart the service"
                    }]
                }),
            }],
            usage: Usage::default(),
        };

        let report = parse_report(&response).unwrap();
        assert_eq!(report.health, "degraded");
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, "HIGH");
    }

    #[test]
    fn errors_when_no_tool_use_block_present() {
        let response = MessagesResponse {
            content: vec![ContentBlock::Text { text: "hello".to_string() }],
            usage: Usage::default(),
        };
        assert!(parse_report(&response).is_err());
    }
}
