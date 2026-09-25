// ==============================================================================
// report.rs - parse the model's triage_report tool call
// ==============================================================================
// Description: Extracts and validates the forced tool_use block. strict:true
//              (spec §5) means the API validates input server-side, but this
//              still checks for the block's presence and required fields
//              defensively rather than assuming the wire never misbehaves.
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-25
// Version: 0.2.0
// ==============================================================================

use crate::anthropic::{ContentBlock, MessagesResponse};
use crate::db::ScoredFinding;
use crate::schema::TRIAGE_REPORT_TOOL_NAME;
use serde::Deserialize;
use std::collections::HashSet;

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

/// A finding the model attributed to a template_hash that was not in the
/// prompt — typically a mis-copied 64-char hex digest. Kept so the caller
/// can log it and flag it in the report rather than drop it silently.
#[derive(Debug)]
pub struct RejectedFinding {
    pub template_hash: String,
    pub issue: String,
}

pub struct ScoredFindings {
    pub kept: Vec<ScoredFinding>,
    pub rejected: Vec<RejectedFinding>,
}

impl Report {
    /// Splits findings by whether their template_hash (trimmed, lowercased)
    /// is one of `sent_hashes`. strict:true validates the JSON shape, not
    /// that the hash refers to real input; without this check one bad copy
    /// violates finding_template_hash_fkey and aborts the whole run.
    pub fn into_scored_findings(self, sent_hashes: &HashSet<String>) -> ScoredFindings {
        let (kept, rejected): (Vec<_>, Vec<_>) = self
            .findings
            .into_iter()
            .map(|f| RawFinding { template_hash: f.template_hash.trim().to_ascii_lowercase(), ..f })
            .partition(|f| sent_hashes.contains(&f.template_hash));

        ScoredFindings {
            kept: kept
                .into_iter()
                .map(|f| ScoredFinding {
                    template_hash: f.template_hash,
                    severity: f.severity,
                    issue: f.issue,
                    recommendation: f.recommendation,
                })
                .collect(),
            rejected: rejected
                .into_iter()
                .map(|f| RejectedFinding { template_hash: f.template_hash, issue: f.issue })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::Usage;
    use serde_json::json;
    use std::collections::HashSet;

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

    fn raw(hash: &str, issue: &str) -> RawFinding {
        RawFinding {
            template_hash: hash.to_string(),
            severity: "HIGH".to_string(),
            service: "plex".to_string(),
            issue: issue.to_string(),
            count: 1,
            first_seen: String::new(),
            last_seen: String::new(),
            recommendation: None,
        }
    }

    fn report_with(findings: Vec<RawFinding>) -> Report {
        Report { summary: String::new(), total_events: 0, health: "healthy".to_string(), findings }
    }

    /// Run 23 (2026-09-23): the model cited a template_hash that was never in
    /// the prompt, the INSERT hit finding_template_hash_fkey and the whole run
    /// died. An unknown hash must be rejected here, not reach Postgres.
    #[test]
    fn drops_findings_whose_hash_was_not_sent() {
        let known = HashSet::from(["a".repeat(64)]);
        let split = report_with(vec![raw(&"a".repeat(64), "real"), raw(&"f".repeat(64), "hallucinated")])
            .into_scored_findings(&known);

        assert_eq!(split.kept.len(), 1);
        assert_eq!(split.kept[0].issue, "real");
        assert_eq!(split.rejected.len(), 1);
        assert_eq!(split.rejected[0].template_hash, "f".repeat(64));
        assert_eq!(split.rejected[0].issue, "hallucinated");
    }

    #[test]
    fn accepts_case_and_whitespace_variants_of_a_sent_hash() {
        let known = HashSet::from(["ab".repeat(32)]);
        let split = report_with(vec![raw(&format!(" {} ", "AB".repeat(32)), "shouted")]).into_scored_findings(&known);

        assert!(split.rejected.is_empty());
        assert_eq!(split.kept[0].template_hash, "ab".repeat(32));
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
