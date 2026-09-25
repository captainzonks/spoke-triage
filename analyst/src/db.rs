// ==============================================================================
// db.rs - Postgres reads/writes for triage-analyst
// ==============================================================================
// Description: Reads a run's pending templates (excluding benign verdicts,
//              spec §6.1), writes findings with a computed status field, and
//              records api_call cost accounting (spec §5/§9).
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-25
// Version: 0.2.0
// ==============================================================================

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use sqlx::Row;

pub struct PendingRun {
    pub run_id: i64,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
}

pub struct PendingTemplate {
    pub template_hash: String,
    pub service_name: String,
    pub logger: String,
    pub template_text: String,
    /// Occurrences inside this run's window (template_occurrence.count).
    pub window_count: i64,
    /// Lifetime occurrences across all runs (log_template.total_count).
    pub total_count: i64,
    /// Lifetime first/last seen — `first_seen >= window_start` means the
    /// template is new this window.
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub exemplar_lines: Vec<String>,
    pub verdict_classification: Option<String>,
    pub verdict_note: Option<String>,
}

pub struct ScoredFinding {
    pub template_hash: String,
    pub severity: String,
    pub issue: String,
    pub recommendation: Option<String>,
}

/// A finding after `write_findings` has computed and persisted its
/// new/recurring/escalating status — the shape the mail report renders from.
pub struct WrittenFinding {
    pub severity: String,
    pub issue: String,
    pub recommendation: Option<String>,
    pub status: &'static str,
}

/// The NEWEST run still in `running` status: collector wrote its aggregates,
/// analyst hasn't processed it yet.
///
/// Newest, not oldest, because the report is about what the infrastructure is
/// doing *now*. A run is only left in `running` when its analyst never
/// finished — an analyst crash, Postgres still replaying WAL after a host
/// boot, an operator Ctrl-C. Draining the oldest such run first means one
/// failed analyst silently offsets every subsequent cycle by one run: each
/// day's timer collects a fresh window, then analyzes and emails the previous
/// day's, with the email's own "Period" line still claiming it covers the last
/// `TRIAGE_LOOKBACK_HOURS`. That state never self-heals. Claiming the newest
/// run keeps every report current; `abandon_superseded_runs` retires the ones
/// skipped over so they don't accumulate.
pub async fn next_pending_run(pool: &PgPool) -> anyhow::Result<Option<PendingRun>> {
    let row = sqlx::query("SELECT id, window_start, window_end FROM run WHERE status = 'running' ORDER BY id DESC LIMIT 1")
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| PendingRun {
        run_id: r.get("id"),
        window_start: r.get("window_start"),
        window_end: r.get("window_end"),
    }))
}

/// Retires every `running` run older than the one being analyzed. Their
/// aggregates (log_template, template_occurrence) are already written and stay
/// queryable for history and trend counts — only the run's lifecycle status
/// changes, so it is no longer a candidate for a future analyst pass.
/// Returns how many rows were retired. See migration 0004 for why this is
/// `abandoned` rather than `failed`.
pub async fn abandon_superseded_runs(pool: &PgPool, current_run_id: i64) -> anyhow::Result<u64> {
    let result = sqlx::query("UPDATE run SET status = 'abandoned' WHERE status = 'running' AND id < $1")
        .bind(current_run_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Every eligible template from this run's occurrences: this window's count
/// from template_occurrence, full-history first/last_seen + total_count from
/// log_template, left-joined to verdict. `benign`-classified templates are
/// excluded here — before the API call, per spec §6.1/§1.1 point 2, not
/// filtered out of the model's response after the fact. Capping to the
/// prompt budget is `select_for_prompt`'s job, not this query's.
pub async fn load_pending_templates(pool: &PgPool, run_id: i64) -> anyhow::Result<Vec<PendingTemplate>> {
    let rows = sqlx::query(
        "SELECT lt.template_hash, lt.service_name, lt.logger, lt.template_text,
                o.count AS window_count, lt.total_count, lt.first_seen, lt.last_seen,
                o.exemplar_lines, v.classification, v.note
         FROM template_occurrence o
         JOIN log_template lt ON lt.template_hash = o.template_hash
         LEFT JOIN verdict v ON v.template_hash = o.template_hash
         WHERE o.run_id = $1
           AND (v.classification IS NULL OR v.classification != 'benign')
         ORDER BY lt.template_hash",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| PendingTemplate {
            template_hash: r.get("template_hash"),
            service_name: r.get("service_name"),
            logger: r.get("logger"),
            template_text: r.get("template_text"),
            window_count: r.get("window_count"),
            total_count: r.get("total_count"),
            first_seen: r.get("first_seen"),
            last_seen: r.get("last_seen"),
            exemplar_lines: r.get("exemplar_lines"),
            verdict_classification: r.get("classification"),
            verdict_note: r.get("note"),
        })
        .collect())
}

/// Picks which templates fit in the single-call prompt
/// (TRIAGE_MAX_TEMPLATES_PER_RUN, see config.rs). Order: templates first seen
/// inside this window, then this window's occurrence count, then hash for a
/// stable tie-break. Ranking by lifetime total_count (the old SQL ORDER BY)
/// let long-running noise crowd out brand-new errors every run. Templates
/// past the cap are not analyzed this run; the caller logs how many.
pub fn select_for_prompt(templates: Vec<PendingTemplate>, window_start: DateTime<Utc>, limit: usize) -> Vec<PendingTemplate> {
    let mut ranked = templates;
    ranked.sort_by(|a, b| {
        let a_new = a.first_seen >= window_start;
        let b_new = b.first_seen >= window_start;
        b_new
            .cmp(&a_new)
            .then_with(|| b.window_count.cmp(&a.window_count))
            .then_with(|| a.template_hash.cmp(&b.template_hash))
    });
    ranked.truncate(limit);
    ranked
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0, // INFO and anything unrecognized
    }
}

/// new/recurring/escalating per spec §5 ("computed from history, never
/// asked of the model" — spec's wording attributes this to "the collector",
/// but collector never sees model output; this repo's design has
/// triage-analyst own it instead, since it's the component that writes
/// `finding` rows). `resolved` is intentionally not auto-detected here: that
/// would mean synthesizing a finding for a template this run *doesn't*
/// flag, which is a different code path (scanning for past CRITICAL/HIGH
/// findings with no current counterpart) that isn't built yet — left as a
/// follow-up, not silently skipped.
async fn compute_status(conn: &mut sqlx::PgConnection, template_hash: &str, current_run_id: i64, current_severity: &str) -> anyhow::Result<&'static str> {
    let prior_severity: Option<String> = sqlx::query_scalar(
        "SELECT severity FROM finding WHERE template_hash = $1 AND run_id != $2 ORDER BY run_id DESC LIMIT 1",
    )
    .bind(template_hash)
    .bind(current_run_id)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(match prior_severity {
        None => "new",
        Some(prev) if severity_rank(current_severity) > severity_rank(&prev) => "escalating",
        Some(_) => "recurring",
    })
}

/// All-or-nothing: one transaction for the whole batch, so a failed INSERT
/// can't leave a partial set of findings behind for the run.
pub async fn write_findings(pool: &PgPool, run_id: i64, findings: &[ScoredFinding]) -> anyhow::Result<Vec<WrittenFinding>> {
    let mut tx = pool.begin().await?;
    let mut written = Vec::with_capacity(findings.len());
    for f in findings {
        let status = compute_status(&mut tx, &f.template_hash, run_id, &f.severity).await?;
        sqlx::query(
            "INSERT INTO finding (run_id, template_hash, severity, issue, recommendation, status)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(run_id)
        .bind(&f.template_hash)
        .bind(&f.severity)
        .bind(&f.issue)
        .bind(&f.recommendation)
        .bind(status)
        .execute(&mut *tx)
        .await?;
        written.push(WrittenFinding {
            severity: f.severity.clone(),
            issue: f.issue.clone(),
            recommendation: f.recommendation.clone(),
            status,
        });
    }
    tx.commit().await?;
    Ok(written)
}

pub async fn write_run_summary(pool: &PgPool, run_id: i64, health_verdict: &str, summary: &str, total_events: i64) -> anyhow::Result<()> {
    sqlx::query("UPDATE run SET health_verdict = $1, summary = $2, total_events = $3 WHERE id = $4")
        .bind(health_verdict)
        .bind(summary)
        .bind(total_events)
        .bind(run_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn mark_run_status(pool: &PgPool, run_id: i64, status: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE run SET status = $1 WHERE id = $2")
        .bind(status)
        .bind(run_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn record_api_call(
    pool: &PgPool,
    run_id: i64,
    model: &str,
    input_tokens: i64,
    output_tokens: i64,
    cache_write_tokens: i64,
    cache_read_tokens: i64,
    latency_ms: i32,
    estimated_cost_usd: f64,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO api_call (run_id, model, input_tokens, output_tokens, cache_write_tokens, cache_read_tokens, latency_ms, estimated_cost_usd)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(run_id)
    .bind(model)
    .bind(input_tokens)
    .bind(output_tokens)
    .bind(cache_write_tokens)
    .bind(cache_read_tokens)
    .bind(latency_ms)
    .bind(estimated_cost_usd)
    .execute(pool)
    .await?;
    Ok(())
}

/// Sum of estimated_cost_usd across api_call rows for the current calendar
/// month, for the budget gate (spec §9).
pub async fn month_to_date_spend_usd(pool: &PgPool) -> anyhow::Result<f64> {
    let total: Option<f64> = sqlx::query_scalar(
        "SELECT SUM(estimated_cost_usd)::float8 FROM api_call WHERE created_at >= date_trunc('month', now())",
    )
    .fetch_one(pool)
    .await?;
    Ok(total.unwrap_or(0.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn tmpl(hash: &str, window_count: i64, lifetime: i64, first_seen: DateTime<Utc>) -> PendingTemplate {
        PendingTemplate {
            template_hash: hash.to_string(),
            service_name: "svc".to_string(),
            logger: "app".to_string(),
            template_text: "t".to_string(),
            window_count,
            total_count: lifetime,
            first_seen,
            last_seen: first_seen,
            exemplar_lines: vec![],
            verdict_classification: None,
            verdict_note: None,
        }
    }

    fn hashes(ts: &[PendingTemplate]) -> Vec<&str> {
        ts.iter().map(|t| t.template_hash.as_str()).collect()
    }

    /// Runs 21-25: ordering by lifetime total_count with LIMIT 150 cut up to
    /// 100 templates first seen in the window (run 24), so new errors never
    /// reached the model. New templates must win the cap, then this window's
    /// volume — lifetime volume must not decide.
    #[test]
    fn select_for_prompt_prefers_new_templates_then_window_count() {
        let window_start = Utc::now() - Duration::hours(24);
        let old = window_start - Duration::days(10);
        let new = window_start + Duration::hours(1);

        let selected = select_for_prompt(
            vec![
                tmpl("old_loud_lifetime", 5, 1_000_000, old),
                tmpl("old_loud_window", 500, 600, old),
                tmpl("new_rare", 1, 1, new),
                tmpl("new_busier", 3, 3, new),
            ],
            window_start,
            3,
        );

        assert_eq!(hashes(&selected), vec!["new_busier", "new_rare", "old_loud_window"]);
    }

    #[test]
    fn select_for_prompt_is_deterministic_on_ties() {
        let window_start = Utc::now();
        let old = window_start - Duration::days(1);
        let selected = select_for_prompt(vec![tmpl("b", 1, 1, old), tmpl("a", 1, 1, old)], window_start, 10);
        assert_eq!(hashes(&selected), vec!["a", "b"]);
    }

    /// Ignored by default — needs the same disposable Postgres as
    /// collector/tests/migrations.rs (TRIAGE_MIGRATION_TEST_ADMIN_URL).
    /// Run 23 left 1 of 13 findings behind when the 2nd INSERT failed:
    /// findings must be written all-or-nothing.
    #[tokio::test]
    #[ignore]
    async fn write_findings_is_all_or_nothing() {
        let url = std::env::var("TRIAGE_MIGRATION_TEST_ADMIN_URL").expect("TRIAGE_MIGRATION_TEST_ADMIN_URL must be set");
        let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&url).await.unwrap();
        sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO triage_app;")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::migrate!("../migrations").run(&pool).await.unwrap();

        let run_id: i64 = sqlx::query_scalar(
            "INSERT INTO run (window_start, window_end, status) VALUES (now() - interval '1 day', now(), 'running') RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO log_template (template_hash, service_name, logger, template_text, first_seen, last_seen, total_count)
             VALUES (repeat('a', 64), 'svc', 'app', 't', now(), now(), 1)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let finding = |hash: String| ScoredFinding { template_hash: hash, severity: "HIGH".into(), issue: "i".into(), recommendation: None };
        let result = write_findings(&pool, run_id, &[finding("a".repeat(64)), finding("f".repeat(64))]).await;
        assert!(result.is_err(), "unknown template_hash must still violate the FK");

        let persisted: i64 = sqlx::query_scalar("SELECT count(*) FROM finding WHERE run_id = $1")
            .bind(run_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(persisted, 0, "a failed batch must not leave partial findings behind");
    }
}
