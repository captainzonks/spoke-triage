// ==============================================================================
// report.rs - parse the model's triage_report tool call
// ==============================================================================
// Description: Extracts and validates the forced tool_use block. strict:true
//              (spec §5) means the API validates input server-side, but this
//              still checks for the block's presence and required fields
//              defensively rather than assuming the wire never misbehaves.
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-10-10
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
    ///
    /// The model may group one root cause across several templates by citing a
    /// list or range ("t1-t3, t5"). A finding stores a single template_hash, so
    /// it is attached to the first cited ref that was sent, and the other sent
    /// refs are named in the issue text. Cited refs that were not sent are
    /// ignored; a finding with no sent ref at all is rejected.
    pub fn into_scored_findings(self, refs: &HashMap<String, String>) -> ScoredFindings {
        let mut kept = Vec::new();
        let mut rejected = Vec::new();
        for f in self.findings {
            let cited = expand_refs(&f.template_ref);
            let mut sent = cited.iter().filter(|r| refs.contains_key(*r));
            let Some(primary) = sent.next() else {
                rejected.push(RejectedFinding { template_ref: f.template_ref, issue: f.issue });
                continue;
            };
            let others: Vec<&str> = sent.map(String::as_str).collect();
            let issue = if others.is_empty() {
                f.issue
            } else {
                format!("{} (Grouped finding: also covers {}.)", f.issue, others.join(", "))
            };
            kept.push(ScoredFinding {
                template_hash: refs[primary].clone(),
                severity: f.severity,
                issue,
                recommendation: f.recommendation,
            });
        }
        ScoredFindings { kept, rejected }
    }
}

/// The model controls the string being expanded, so a range is cut off after
/// this many refs past its start; a run never sends anywhere near that many.
const MAX_RANGE_SPAN: u64 = 1024;

/// "t12", " T12 " and a bare "12" all mean the template sent as "t12".
fn normalize_ref(raw: &str) -> String {
    let r = raw.trim().to_ascii_lowercase();
    if !r.is_empty() && r.chars().all(|c| c.is_ascii_digit()) { format!("t{r}") } else { r }
}

/// The number in a single ref ("t12" -> 12), or None if it is not a ref.
fn ref_number(raw: &str) -> Option<u64> {
    normalize_ref(raw).strip_prefix('t')?.parse().ok()
}

/// Closes up whitespace around range dashes so "t1 - t3" is one token.
fn tighten_range_dashes(raw: &str) -> String {
    let mut s = raw.replace('\u{2013}', "-");
    while s.contains(" -") || s.contains("- ") {
        s = s.replace(" -", "-").replace("- ", "-");
    }
    s
}

/// Splits a template_ref string into single normalized refs in cited order,
/// without duplicates. Accepts lists separated by commas, semicolons or
/// whitespace, and ranges such as "t1-t3" (either order, hyphen or en dash).
/// A token that is not a ref or a range is kept as is, so it fails the lookup
/// like any other unknown ref.
fn expand_refs(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |r: String| {
        if !out.contains(&r) {
            out.push(r);
        }
    };
    let tight = tighten_range_dashes(raw);
    for token in tight.split(|c: char| c == ',' || c == ';' || c.is_whitespace()).filter(|t| !t.is_empty()) {
        let bounds = token.split_once('-').and_then(|(a, b)| Some((ref_number(a)?, ref_number(b)?)));
        match bounds {
            Some((a, b)) => {
                let (lo, hi) = (a.min(b), a.max(b));
                for n in lo..=hi.min(lo.saturating_add(MAX_RANGE_SPAN)) {
                    push(format!("t{n}"));
                }
            }
            None => push(normalize_ref(token)),
        }
    }
    out
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

    fn refs_t1_to_t6() -> HashMap<String, String> {
        ('1'..='6').map(|n| (format!("t{n}"), n.to_string().repeat(64))).collect()
    }

    /// Run 40 (2026-10-10): the model grouped one root cause across many
    /// templates as "t1-t12, t14-t16" and "t33, t64"; both findings were dropped.
    #[test]
    fn keeps_a_comma_list_on_its_first_resolvable_ref() {
        let split = report_with(vec![raw("t2, t3", "grouped")]).into_scored_findings(&refs_t1_to_t6());

        assert!(split.rejected.is_empty());
        assert_eq!(split.kept.len(), 1);
        assert_eq!(split.kept[0].template_hash, "2".repeat(64));
    }

    #[test]
    fn expands_ranges_and_lists_the_other_refs_in_the_issue_text() {
        let split = report_with(vec![raw("t1-t3, t5", "api timeouts")]).into_scored_findings(&refs_t1_to_t6());

        assert!(split.rejected.is_empty());
        assert_eq!(split.kept[0].template_hash, "1".repeat(64));
        assert_eq!(split.kept[0].issue, "api timeouts (Grouped finding: also covers t2, t3, t5.)");
    }

    #[test]
    fn a_single_ref_leaves_the_issue_text_untouched() {
        let split = report_with(vec![raw("t4", "plain")]).into_scored_findings(&refs_t1_to_t6());
        assert_eq!(split.kept[0].issue, "plain");
    }

    #[test]
    fn accepts_bare_number_and_reversed_ranges_and_other_separators() {
        let split = report_with(vec![raw("3-1", "reversed"), raw("t2 ; T4  t5", "mixed"), raw("t1\u{2013}t2", "en dash")])
            .into_scored_findings(&refs_t1_to_t6());

        assert!(split.rejected.is_empty());
        assert_eq!(split.kept[0].issue, "reversed (Grouped finding: also covers t2, t3.)");
        assert_eq!(split.kept[1].issue, "mixed (Grouped finding: also covers t4, t5.)");
        assert_eq!(split.kept[2].issue, "en dash (Grouped finding: also covers t2.)");
    }

    #[test]
    fn spaces_around_a_range_dash_do_not_split_the_range() {
        let split = report_with(vec![raw("t1 - t3", "spaced")]).into_scored_findings(&refs_t1_to_t6());
        assert_eq!(split.kept[0].issue, "spaced (Grouped finding: also covers t2, t3.)");
    }

    #[test]
    fn repeated_refs_are_listed_once() {
        let split = report_with(vec![raw("t1, t2, t2, t1-t2", "dupes")]).into_scored_findings(&refs_t1_to_t6());
        assert_eq!(split.kept[0].issue, "dupes (Grouped finding: also covers t2.)");
    }

    /// A list with at least one real ref is kept; refs outside the sent set are
    /// ignored rather than sinking the whole finding.
    #[test]
    fn ignores_unsent_refs_in_a_list_that_has_a_sent_one() {
        let split = report_with(vec![raw("t99, t3", "partly real")]).into_scored_findings(&refs_t1_to_t6());

        assert!(split.rejected.is_empty());
        assert_eq!(split.kept[0].template_hash, "3".repeat(64));
        assert_eq!(split.kept[0].issue, "partly real");
    }

    #[test]
    fn rejects_a_list_or_range_with_no_sent_ref() {
        let split = report_with(vec![raw("t90-t95", "range"), raw("t98, t99", "list")]).into_scored_findings(&refs_t1_to_t6());

        assert!(split.kept.is_empty());
        assert_eq!(split.rejected.len(), 2);
        assert_eq!(split.rejected[0].template_ref, "t90-t95");
        assert_eq!(split.rejected[1].template_ref, "t98, t99");
    }

    /// The model controls this string; a hostile or confused range must not
    /// allocate or loop in proportion to its size.
    #[test]
    fn a_huge_range_is_bounded() {
        let split = report_with(vec![raw("t1-t4000000000", "runaway")]).into_scored_findings(&refs_t1_to_t6());

        assert_eq!(split.kept.len(), 1);
        assert_eq!(split.kept[0].issue, "runaway (Grouped finding: also covers t2, t3, t4, t5, t6.)");
    }

    #[test]
    fn rejects_empty_and_separator_only_refs() {
        let split = report_with(vec![raw("", "empty"), raw(" , ; ", "separators")]).into_scored_findings(&refs_t1_to_t6());
        assert!(split.kept.is_empty());
        assert_eq!(split.rejected.len(), 2);
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
