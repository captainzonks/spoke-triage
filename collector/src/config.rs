// ==============================================================================
// config.rs - triage-collector environment configuration
// ==============================================================================
// Description: Env-var-driven config, no config file — matches the
//              hub-and-spoke pattern of injecting config via docker-compose
//              environment (docs/spec.md, stack.yml). DATABASE_URL is built
//              from POSTGRES_HOST/POSTGRES_PORT/TRIAGE_POSTGRES_DB plus the
//              triage_app password, read from TRIAGE_APP_PSQL_PASSWORD_FILE
//              via spoke_triage_common::secret — no plaintext password in
//              the environment (spec §6 role model).
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-09
// Version: 0.1.0
// ==============================================================================

pub struct Config {
    pub database_url: String,
    pub loki_base_url: String,
    pub loki_tenant_id: String,
    pub lookback_hours: i64,
    pub exemplar_limit: usize,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Config {
            database_url: spoke_triage_common::secret::build_postgres_url("TRIAGE_POSTGRES_DB")?,
            loki_base_url: env_or("TRIAGE_LOKI_BASE_URL", "http://loki:3100"),
            loki_tenant_id: env_or("TRIAGE_LOKI_TENANT_ID", "fake"),
            lookback_hours: env_or("TRIAGE_LOOKBACK_HOURS", "24").parse()?,
            exemplar_limit: env_or("TRIAGE_EXEMPLAR_LIMIT", "3").parse()?,
        })
    }
}

fn env_or(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}
