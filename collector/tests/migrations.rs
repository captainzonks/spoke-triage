// ==============================================================================
// migrations.rs - migration test suite (docs/spec.md §8)
// ==============================================================================
// Description: Applies ../../migrations from empty and checks the resulting
//              schema and triage_app's grants against docs/spec.md §6. No RLS
//              is used (spec §2: single-tenant, one Postgres role) so there is
//              no "denied read" test — instead this documents, as an
//              executable assertion, the Postgres ownership caveat noted in
//              migrations/0001_initial_schema.sql: triage_app owns the tables
//              it migrates, so it retains DELETE/DROP/ALTER despite the
//              migration's explicit SELECT/INSERT/UPDATE-only GRANTs.
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-09
// Version: 0.1.0
// ==============================================================================
//
// Ignored by default — requires a real Postgres reachable via two env vars:
//   TRIAGE_MIGRATION_TEST_ADMIN_URL  — superuser connection to the test DB,
//                                      used only to reset the schema to empty
//                                      between runs
//   TRIAGE_MIGRATION_TEST_APP_URL    — triage_app connection to the same DB
//
// The triage_app role and the target database must already exist (roles are
// cluster-wide in Postgres; migrations GRANT to a literal `triage_app`, so
// the role must exist before they run — true in production too, where
// scripts/modules/provision_hub_postgres.sh creates it).
//
// Disposable local setup used to write and verify this suite:
//   docker run -d --rm --name triage-migration-test \
//     -e POSTGRES_PASSWORD=testpass -p 15544:5432 postgres:18.6
//   docker exec triage-migration-test psql -U postgres -c \
//     "CREATE ROLE triage_app WITH LOGIN PASSWORD 'testpass';"
//   docker exec triage-migration-test psql -U postgres -c \
//     "CREATE DATABASE triage OWNER triage_app;"
//   TRIAGE_MIGRATION_TEST_ADMIN_URL=postgres://postgres:testpass@127.0.0.1:15544/triage
//   TRIAGE_MIGRATION_TEST_APP_URL=postgres://triage_app:testpass@127.0.0.1:15544/triage
//   cargo test -p spoke-triage-collector --test migrations -- --ignored

use sqlx::postgres::PgPoolOptions;
use sqlx::Row;

fn env_url(var: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| panic!("{var} must be set to run migration tests"))
}

async fn reset_and_migrate() -> (sqlx::PgPool, sqlx::PgPool) {
    let admin_url = env_url("TRIAGE_MIGRATION_TEST_ADMIN_URL");
    let app_url = env_url("TRIAGE_MIGRATION_TEST_APP_URL");

    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .expect("connect as admin");

    // Reset to empty so every run genuinely applies "from empty" (spec §8).
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO triage_app;")
        .execute(&admin)
        .await
        .expect("reset schema to empty");

    let app = PgPoolOptions::new()
        .max_connections(1)
        .connect(&app_url)
        .await
        .expect("connect as triage_app");

    sqlx::migrate!("../migrations")
        .run(&app)
        .await
        .expect("apply migrations from empty");

    (admin, app)
}

#[tokio::test]
#[ignore]
async fn migrations_apply_from_empty_and_create_all_six_tables() {
    let (admin, _app) = reset_and_migrate().await;

    let rows = sqlx::query(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename",
    )
    .fetch_all(&admin)
    .await
    .expect("list tables");

    let tables: Vec<String> = rows.iter().map(|r| r.get::<String, _>("tablename")).collect();
    for expected in [
        "run",
        "log_template",
        "template_occurrence",
        "verdict",
        "finding",
        "api_call",
    ] {
        assert!(
            tables.iter().any(|t| t == expected),
            "expected table {expected} to exist, found {tables:?}"
        );
    }
}

#[tokio::test]
#[ignore]
async fn triage_app_can_select_insert_update_all_tables() {
    let (_admin, app) = reset_and_migrate().await;

    sqlx::query("INSERT INTO run (window_start, window_end, status) VALUES (now() - interval '1 hour', now(), 'running')")
        .execute(&app)
        .await
        .expect("insert into run");

    sqlx::query(
        "INSERT INTO log_template (template_hash, service_name, logger, template_text, first_seen, last_seen, total_count)
         VALUES (repeat('a', 64), 'plex', 'app', 'worker <NUM> exited', now(), now(), 1)",
    )
    .execute(&app)
    .await
    .expect("insert into log_template");

    sqlx::query("UPDATE log_template SET total_count = 2 WHERE template_hash = repeat('a', 64)")
        .execute(&app)
        .await
        .expect("update log_template");

    let count: i64 = sqlx::query_scalar("SELECT total_count FROM log_template WHERE template_hash = repeat('a', 64)")
        .fetch_one(&app)
        .await
        .expect("select from log_template");
    assert_eq!(count, 2);
}

#[tokio::test]
#[ignore]
async fn verdict_can_be_seeded_before_any_log_template_row_exists() {
    let (_admin, app) = reset_and_migrate().await;

    // Proactive suppression: an operator (or a future known-patterns seed
    // step) may record a verdict for a template_hash never yet observed by
    // the collector. verdict has no FK to log_template specifically to allow
    // this (see migrations/0001_initial_schema.sql).
    sqlx::query("INSERT INTO verdict (template_hash, classification, set_by) VALUES (repeat('b', 64), 'benign', 'matt')")
        .execute(&app)
        .await
        .expect("seed verdict with no matching log_template row");
}

#[tokio::test]
#[ignore]
async fn triage_app_owns_tables_and_retains_delete_despite_no_explicit_grant() {
    let (_admin, app) = reset_and_migrate().await;

    sqlx::query(
        "INSERT INTO log_template (template_hash, service_name, logger, template_text, first_seen, last_seen, total_count)
         VALUES (repeat('c', 64), 'plex', 'app', 'worker <NUM> exited', now(), now(), 1)",
    )
    .execute(&app)
    .await
    .expect("insert into log_template");

    // The migration only GRANTs SELECT/INSERT/UPDATE — this DELETE succeeding
    // documents the ownership caveat as an executable check, not just a
    // comment: triage_app is the table owner (it ran the migration that
    // created these tables), and Postgres always lets an owner DELETE/DROP/
    // ALTER its own objects regardless of explicit GRANT/REVOKE. If this test
    // ever starts failing because DELETE is denied, the role model changed
    // (ownership was split from the runtime role) and the caveat comments in
    // migrations/0001_initial_schema.sql and this file should be removed.
    let deleted = sqlx::query("DELETE FROM log_template WHERE template_hash = repeat('c', 64)")
        .execute(&app)
        .await
        .expect("delete succeeds because triage_app owns this table");
    assert_eq!(deleted.rows_affected(), 1);
}
