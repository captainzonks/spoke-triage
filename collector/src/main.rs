// ==============================================================================
// main.rs - triage-collector entrypoint
// ==============================================================================
// Description: No-egress side of spoke-triage (docs/spec.md §3.1). Queries
//              Loki, normalizes/aggregates, writes to Postgres. Never talks
//              to the internet, never touches the Anthropic API.
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-09
// Version: 0.1.0
// ==============================================================================

mod aggregate;
mod config;
mod db;
mod loki;

use chrono::Utc;
use config::Config;
use loki::{LokiClient, SEVERITY_QUERIES};
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::from_env()?;
    // Spec §8: "query, normalize, aggregate ... skip ... print what would
    // have happened." No Postgres connection at all in dry-run — this half
    // of the pipeline never calls a paid API, so the only side effect worth
    // suppressing is the write; skipping the connection too means dry-run
    // works even before Postgres is reachable.
    let dry_run = std::env::args().any(|a| a == "--dry-run");

    let window_end = Utc::now();
    let window_start = window_end - chrono::Duration::hours(cfg.lookback_hours);
    let start_ns = window_start.timestamp_nanos_opt().unwrap_or(0);
    let end_ns = window_end.timestamp_nanos_opt().unwrap_or(0);

    let client = LokiClient::new(cfg.loki_base_url.clone(), cfg.loki_tenant_id.clone());

    let mut streams_by_bucket = Vec::with_capacity(SEVERITY_QUERIES.len());
    for (label, query, limit) in SEVERITY_QUERIES {
        match client.query_range(query, start_ns, end_ns, *limit).await {
            Ok(streams) => {
                let entries: usize = streams.iter().map(|s| s.values.len()).sum();
                eprintln!("  {label}: {entries} entries");
                streams_by_bucket.push((*label, streams));
            }
            Err(err) => {
                // Match spoke_log_analysis.sh's degrade-not-fail behavior for
                // a single failed query bucket (line 174-178 in the original
                // script): warn and continue with an empty result for this
                // bucket rather than aborting the whole run.
                eprintln!("  WARN: query '{label}' failed: {err}");
                streams_by_bucket.push((*label, Vec::new()));
            }
        }
    }

    let templates = aggregate::aggregate(&streams_by_bucket, cfg.exemplar_limit);
    eprintln!("aggregated to {} distinct templates", templates.len());

    if dry_run {
        println!("=== DRY RUN — window {window_start} .. {window_end} — no Postgres writes ===");
        for t in &templates {
            println!(
                "[{}] {}/{} x{} ({} .. {})\n  {}",
                &t.template_hash[..12],
                t.service_name,
                t.logger,
                t.count,
                t.first_seen,
                t.last_seen,
                t.template_text
            );
        }
        println!("{} distinct templates would be written to log_template/template_occurrence.", templates.len());
        return Ok(());
    }

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&cfg.database_url)
        .await?;

    sqlx::migrate!("../migrations").run(&pool).await?;

    let run_id = db::start_run(&pool, window_start, window_end).await?;
    eprintln!("run {run_id}: window {window_start} .. {window_end}");

    match db::write_aggregates(&pool, run_id, window_start, window_end, &templates).await {
        Ok(()) => {
            // Left as "running": triage-analyst owns the completed/failed/
            // budget_exhausted transition once it has classified this run's
            // templates (spec §5).
        }
        Err(err) => {
            db::mark_run_status(&pool, run_id, "failed").await.ok();
            return Err(err);
        }
    }

    Ok(())
}
