// ==============================================================================
// report.rs - parse the model's triage_report tool call
// ==============================================================================
// Description: Extracts and validates the forced tool_use block. strict:true
//              (spec §5) means the API validates input server-side, but this
//              still checks for the block's presence and required fields
//              defensively rather than assuming the wire never misbehaves.
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-10-02
// Version: 0.3.0
// ==============================================================================

use crate::anthropic::{ContentBlock, MessagesResponse};
use crate::db::ScoredFinding;
use crate::schema::TRIAGE_REPORT_TOOL_NAME;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct Report {
    pub summary: String,
    pub total_events: i64,
    pub health: String,
    pub findings: Vec<RawFinding>,
}

#[derive(Debug, Deserialize)]
pub struct RawFinding {
    pub template_ref: String,
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

/// A finding the model attributed to a template_ref that was not in the
/// prompt. Kept so the caller can log it and flag it in the report rather
/// than drop it silently.
#[derive(Debug)]
pub struct RejectedFinding {
    pub template_ref: String,
    pub issue: String,
}

pub struct ScoredFindings {
    pub kept: Vec<ScoredFinding>,
    pub rejected: Vec<RejectedFinding>,
}

impl Report {
    /// Resolves each finding's template_ref (see prompt::template_ref) to the
    /// template_hash it stands for, using `refs` from prompt::template_ref_map.
    /// strict:true validates the JSON shape, not that the ref was sent; an
    /// unresolvable ref is rejected here instead of violating
    /// finding_template_hash_fkey and aborting the whole run.
    pub fn into_scored_findings(self, refs: &HashMap<String, String>) -> ScoredFindings {
        let mut kept = Vec::new();
        let mut rejected = Vec::new();
        for f in self.findings {
            match refs.get(&normalize_ref(&f.template_ref)) {
                Some(hash) => kept.push(ScoredFinding {
                    template_hash: hash.clone(),
                    severity: f.severity,
                    issue: f.issue,
                    recommendation: f.recommendation,
                }),
                None => rejected.push(RejectedFinding { template_ref: f.template_ref, issue: f.issue }),
            }
        }
        ScoredFindings { kept, rejected }
    }
}

/// "t12", " T12 " and a bare "12" all mean the template sent as "t12".
fn normalize_ref(raw: &str) -> String {
    let r = raw.trim().to_ascii_lowercase();
    if !r.is_empty() && r.chars().all(|c| c.is_ascii_digit()) { format!("t{r}") } else { r }
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
                        "template_ref": "t1",
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

    fn raw(template_ref: &str, issue: &str) -> RawFinding {
        RawFinding {
            template_ref: template_ref.to_string(),
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

    fn refs() -> HashMap<String, String> {
        HashMap::from([("t1".to_string(), "a".repeat(64)), ("t2".to_string(), "b".repeat(64))])
    }

    /// Run 23 (2026-09-23): the model cited a template_hash that was never in
    /// the prompt, the INSERT hit finding_template_hash_fkey and the whole run
    /// died. An unknown ref must be rejected here, not reach Postgres.
    #[test]
    fn drops_findings_whose_ref_was_not_sent() {
        let split = report_with(vec![raw("t2", "real"), raw("t99", "hallucinated")]).into_scored_findings(&refs());

        assert_eq!(split.kept.len(), 1);
        assert_eq!(split.kept[0].issue, "real");
        assert_eq!(split.kept[0].template_hash, "b".repeat(64));
        assert_eq!(split.rejected.len(), 1);
        assert_eq!(split.rejected[0].template_ref, "t99");
        assert_eq!(split.rejected[0].issue, "hallucinated");
    }

    #[test]
    fn accepts_case_whitespace_and_bare_number_variants_of_a_ref() {
        let split = report_with(vec![raw(" T1 ", "shouted"), raw("2", "bare")]).into_scored_findings(&refs());

        assert!(split.rejected.is_empty());
        assert_eq!(split.kept[0].template_hash, "a".repeat(64));
        assert_eq!(split.kept[1].template_hash, "b".repeat(64));
    }

    /// Runs 38-39 (2026-10-01/02): full digests came back with an inserted
    /// character or a half-invented tail. Hashes are no longer accepted at all.
    #[test]
    fn rejects_a_full_hash_in_place_of_a_ref() {
        let split = report_with(vec![raw(&"a".repeat(64), "old style")]).into_scored_findings(&refs());
        assert!(split.kept.is_empty());
        assert_eq!(split.rejected.len(), 1);
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
