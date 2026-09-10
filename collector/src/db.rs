// ==============================================================================
// db.rs - Postgres writes for a collector run
// ==============================================================================
// Description: Creates the run row and upserts log_template/template_occurrence
//              per docs/spec.md §6. Connects as triage_app (migrations/).
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-09
// Version: 0.1.0
// ==============================================================================

use crate::aggregate::AggregatedTemplate;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

pub async fn start_run(pool: &PgPool, window_start: DateTime<Utc>, window_end: DateTime<Utc>) -> anyhow::Result<i64> {
    let id = sqlx::query_scalar(
        "INSERT INTO run (window_start, window_end, status) VALUES ($1, $2, 'running') RETURNING id",
    )
    .bind(window_start)
    .bind(window_end)
    .fetch_one(pool)
    .await?;
    Ok(id)
}

pub async fn mark_run_status(pool: &PgPool, run_id: i64, status: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE run SET status = $1 WHERE id = $2")
        .bind(status)
        .bind(run_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Upserts log_template (cumulative across all runs) and inserts one
/// template_occurrence row per template for this run/window (spec §6).
/// Templates whose classification is `benign` are still recorded here —
/// suppression from the API call happens in triage-analyst (spec §6.1), not
/// in the collector, so history/counts stay complete even for suppressed
/// templates.
pub async fn write_aggregates(
    pool: &PgPool,
    run_id: i64,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    templates: &[AggregatedTemplate],
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;

    for t in templates {
        sqlx::query(
            "INSERT INTO log_template (template_hash, service_name, logger, template_text, first_seen, last_seen, total_count)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (template_hash) DO UPDATE SET
                 first_seen = LEAST(log_template.first_seen, EXCLUDED.first_seen),
                 last_seen = GREATEST(log_template.last_seen, EXCLUDED.last_seen),
                 total_count = log_template.total_count + EXCLUDED.total_count",
        )
        .bind(&t.template_hash)
        .bind(&t.service_name)
        .bind(&t.logger)
        .bind(&t.template_text)
        .bind(t.first_seen)
        .bind(t.last_seen)
        .bind(t.count)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO template_occurrence (template_hash, run_id, service_name, count, window_start, window_end, exemplar_lines)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&t.template_hash)
        .bind(run_id)
        .bind(&t.service_name)
        .bind(t.count)
        .bind(window_start)
        .bind(window_end)
        .bind(&t.exemplar_lines)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(())
}
