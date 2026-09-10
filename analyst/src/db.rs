// ==============================================================================
// db.rs - Postgres reads/writes for triage-analyst
// ==============================================================================
// Description: Reads a run's pending templates (excluding benign verdicts,
//              spec §6.1), writes findings with a computed status field, and
//              records api_call cost accounting (spec §5/§9).
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-09
// Version: 0.1.0
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
    pub total_count: i64,
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

/// The oldest run still in `running` status: collector wrote its aggregates,
/// analyst hasn't processed it yet.
pub async fn next_pending_run(pool: &PgPool) -> anyhow::Result<Option<PendingRun>> {
    let row = sqlx::query("SELECT id, window_start, window_end FROM run WHERE status = 'running' ORDER BY id ASC LIMIT 1")
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| PendingRun {
        run_id: r.get("id"),
        window_start: r.get("window_start"),
        window_end: r.get("window_end"),
    }))
}

/// Templates from this run's occurrences, joined to log_template for
/// full-history first/last_seen + total_count, and left-joined to verdict.
/// `benign`-classified templates are excluded here — before the API call,
/// per spec §6.1/§1.1 point 2, not filtered out of the model's response
/// after the fact. `limit` bounds the single-call prompt to the model's
/// context window (TRIAGE_MAX_TEMPLATES_PER_RUN, see config.rs) — templates
/// beyond it wait for a future run.
pub async fn load_pending_templates(pool: &PgPool, run_id: i64, limit: i64) -> anyhow::Result<Vec<PendingTemplate>> {
    let rows = sqlx::query(
        "SELECT lt.template_hash, lt.service_name, lt.logger, lt.template_text,
                lt.total_count, lt.first_seen, lt.last_seen,
                o.exemplar_lines, v.classification, v.note
         FROM template_occurrence o
         JOIN log_template lt ON lt.template_hash = o.template_hash
         LEFT JOIN verdict v ON v.template_hash = o.template_hash
         WHERE o.run_id = $1
           AND (v.classification IS NULL OR v.classification != 'benign')
         ORDER BY lt.total_count DESC
         LIMIT $2",
    )
    .bind(run_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| PendingTemplate {
            template_hash: r.get("template_hash"),
            service_name: r.get("service_name"),
            logger: r.get("logger"),
            template_text: r.get("template_text"),
            total_count: r.get("total_count"),
            first_seen: r.get("first_seen"),
            last_seen: r.get("last_seen"),
            exemplar_lines: r.get("exemplar_lines"),
            verdict_classification: r.get("classification"),
            verdict_note: r.get("note"),
        })
        .collect())
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
async fn compute_status(pool: &PgPool, template_hash: &str, current_run_id: i64, current_severity: &str) -> anyhow::Result<&'static str> {
    let prior_severity: Option<String> = sqlx::query_scalar(
        "SELECT severity FROM finding WHERE template_hash = $1 AND run_id != $2 ORDER BY run_id DESC LIMIT 1",
    )
    .bind(template_hash)
    .bind(current_run_id)
    .fetch_optional(pool)
    .await?;

    Ok(match prior_severity {
        None => "new",
        Some(prev) if severity_rank(current_severity) > severity_rank(&prev) => "escalating",
        Some(_) => "recurring",
    })
}

pub async fn write_findings(pool: &PgPool, run_id: i64, findings: &[ScoredFinding]) -> anyhow::Result<Vec<WrittenFinding>> {
    let mut written = Vec::with_capacity(findings.len());
    for f in findings {
        let status = compute_status(pool, &f.template_hash, run_id, &f.severity).await?;
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
        .execute(pool)
        .await?;
        written.push(WrittenFinding {
            severity: f.severity.clone(),
            issue: f.issue.clone(),
            recommendation: f.recommendation.clone(),
            status,
        });
    }
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
