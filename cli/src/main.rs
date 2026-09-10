// ==============================================================================
// main.rs - triage-cli
// ==============================================================================
// Description: Operator CLI for spoke-triage. Currently one subcommand,
//              `verdict set`, per docs/spec.md §6.1 — record a suppression
//              verdict without editing files. Hand-rolled argument parsing
//              (no clap) — a single three/four-arg subcommand doesn't
//              justify the dependency (docs/spec.md §1.1 optimization
//              priority applies to deps, not just API cost). Bundled into
//              the triage-analyst image and invoked via
//              `docker compose exec triage-analyst triage-cli ...`, so it
//              builds DATABASE_URL from the same POSTGRES_HOST/PORT/DB +
//              _FILE secret vars analyst's own config.rs uses, not a
//              standalone DATABASE_URL (the container never has one set).
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-09
// Version: 0.1.0
// ==============================================================================

use sqlx::postgres::PgPoolOptions;

const USAGE: &str = "\
Usage:
  triage-cli verdict set <template_hash> <benign|known-issue|watch> [--note TEXT] [--set-by NAME]

Environment (inherited from the triage-analyst container):
  POSTGRES_HOST, POSTGRES_PORT, TRIAGE_POSTGRES_DB, TRIAGE_APP_PSQL_PASSWORD_FILE
  USER           default for --set-by if not given
";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        Some("verdict") => match args.get(1).map(String::as_str) {
            Some("set") => verdict_set(&args[2..]).await,
            _ => {
                eprint!("{USAGE}");
                std::process::exit(2);
            }
        },
        _ => {
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    }
}

async fn verdict_set(args: &[String]) -> anyhow::Result<()> {
    let Some(template_hash) = args.first() else {
        anyhow::bail!("missing <template_hash>\n{USAGE}");
    };
    let Some(classification) = args.get(1) else {
        anyhow::bail!("missing <classification>\n{USAGE}");
    };

    if !matches!(classification.as_str(), "benign" | "known-issue" | "watch") {
        anyhow::bail!("classification must be one of: benign, known-issue, watch (got {classification:?})");
    }
    if template_hash.len() != 64 || !template_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("template_hash must be a 64-char hex SHA-256 digest (got {template_hash:?})");
    }

    let mut note: Option<String> = None;
    let mut set_by: Option<String> = None;
    let mut rest = args[2..].iter();
    while let Some(flag) = rest.next() {
        match flag.as_str() {
            "--note" => note = rest.next().cloned(),
            "--set-by" => set_by = rest.next().cloned(),
            other => anyhow::bail!("unrecognized flag {other:?}\n{USAGE}"),
        }
    }
    let set_by = set_by.or_else(|| std::env::var("USER").ok()).unwrap_or_else(|| "unknown".to_string());

    let database_url = spoke_triage_common::secret::build_postgres_url("TRIAGE_POSTGRES_DB")?;
    let pool = PgPoolOptions::new().max_connections(1).connect(&database_url).await?;

    sqlx::query(
        "INSERT INTO verdict (template_hash, classification, note, set_by, set_at)
         VALUES ($1, $2, $3, $4, now())
         ON CONFLICT (template_hash) DO UPDATE SET
             classification = EXCLUDED.classification,
             note = EXCLUDED.note,
             set_by = EXCLUDED.set_by,
             set_at = now()",
    )
    .bind(template_hash)
    .bind(classification)
    .bind(&note)
    .bind(&set_by)
    .execute(&pool)
    .await?;

    println!("verdict set: {template_hash} -> {classification} (by {set_by})");
    Ok(())
}
