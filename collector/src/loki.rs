// ==============================================================================
// loki.rs - Loki query_range client
// ==============================================================================
// Description: Queries Loki for the same four severity buckets as
//              spoke_log_analysis.sh (docs/spec.md §3.1 step 1), carried over
//              verbatim from scripts/maintenance/spoke_log_analysis.sh lines
//              192-195 in the spoke repo. Log queries require query_range —
//              Loki's instant-query endpoint rejects log-selector queries.
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-09
// Version: 0.1.0
// ==============================================================================

use serde::Deserialize;
use std::collections::HashMap;

/// (label, LogQL query, limit) — verbatim from spoke_log_analysis.sh.
pub const SEVERITY_QUERIES: &[(&str, &str, u32)] = &[
    (
        "critical_fatal",
        r#"{job="docker"} |~ `(?i)(\bfatal\b|\bpanic\b|\bsegfault\b|out of memory|\boom[-_ ]?kill|core dump|\bSIGKILL\b|\bSIGSEGV\b|\bSIGABRT\b)`"#,
        5000,
    ),
    (
        "errors",
        r#"{job="docker"} | json | level=~`error|err|ERROR`"#,
        2000,
    ),
    (
        "warnings",
        r#"{job="docker"} | json | level=~`warn|warning|WARN|WARNING`"#,
        1000,
    ),
    (
        "system_issues",
        r#"{job="system"} |~ `(?i)(\berror\b|\bfailed\b|\bcritical\b|\bpanic\b|\boom[-_ ]?kill)`"#,
        5000,
    ),
];

#[derive(Debug, Deserialize)]
struct QueryRangeResponse {
    data: QueryRangeData,
}

#[derive(Debug, Deserialize)]
struct QueryRangeData {
    result: Vec<Stream>,
}

#[derive(Debug, Deserialize)]
pub struct Stream {
    pub stream: HashMap<String, String>,
    /// [unix_nanos_as_string, log_line] per entry; a 3rd structured-metadata
    /// element may be present depending on Loki version, hence Vec<String>
    /// rather than a fixed-size tuple.
    pub values: Vec<Vec<String>>,
}

pub struct LokiClient {
    http: reqwest::Client,
    base_url: String,
    tenant_id: String,
}

impl LokiClient {
    pub fn new(base_url: String, tenant_id: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url,
            tenant_id,
        }
    }

    /// `start_ns`/`end_ns` are Unix nanosecond timestamps, per Loki's
    /// query_range contract.
    pub async fn query_range(
        &self,
        query: &str,
        start_ns: i64,
        end_ns: i64,
        limit: u32,
    ) -> anyhow::Result<Vec<Stream>> {
        let url = format!("{}/loki/api/v1/query_range", self.base_url);
        let response = self
            .http
            .get(&url)
            .header("X-Scope-OrgID", &self.tenant_id)
            .query(&[
                ("query", query.to_string()),
                ("start", start_ns.to_string()),
                ("end", end_ns.to_string()),
                ("limit", limit.to_string()),
            ])
            .timeout(std::time::Duration::from_secs(60))
            .send()
            .await?
            .error_for_status()?
            .json::<QueryRangeResponse>()
            .await?;

        Ok(response.data.result)
    }
}
