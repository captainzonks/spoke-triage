// ==============================================================================
// secret.rs - _FILE-convention secret loading
// ==============================================================================
// Description: Reads a secret from the path named by `file_var` (Spoke's
//              standard `_FILE` env var convention, docs/secrets_support.md
//              in the spoke repo) if set, else falls back to `plain_var` for
//              local development. Matches spoke-trek's own Rust-native
//              pattern rather than a shell-entrypoint wrapper — spec.md §3.2
//              speculated a shell entrypoint before this was implemented;
//              reading the file directly in Rust is simpler and consistent
//              with the one other Rust module in Spoke.
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-09
// Version: 0.1.0
// ==============================================================================

pub fn read_secret(file_var: &str, plain_var: &str) -> anyhow::Result<String> {
    if let Ok(path) = std::env::var(file_var) {
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("failed to read {file_var}={path}: {e}"))?;
        return Ok(contents.trim().to_string());
    }
    std::env::var(plain_var).map_err(|_| anyhow::anyhow!("either {file_var} or {plain_var} must be set"))
}

/// Builds a `postgres://triage_app:...@host:port/db` URL from Spoke's
/// POSTGRES_HOST/POSTGRES_PORT hub vars, `db_name_var`'s module-specific DB
/// name var, and the triage_app password (read via `read_secret`).
/// Percent-encodes the password: Spoke's secret convention generates
/// passwords with `openssl rand -base64 32`, whose alphabet (`+`, `/`, `=`)
/// is not URL-safe unescaped.
pub fn build_postgres_url(db_name_var: &str) -> anyhow::Result<String> {
    let host = std::env::var("POSTGRES_HOST").map_err(|_| anyhow::anyhow!("POSTGRES_HOST must be set"))?;
    let port = std::env::var("POSTGRES_PORT").unwrap_or_else(|_| "5432".to_string());
    let db = std::env::var(db_name_var).map_err(|_| anyhow::anyhow!("{db_name_var} must be set"))?;
    let password = read_secret("TRIAGE_APP_PSQL_PASSWORD_FILE", "TRIAGE_APP_PSQL_PASSWORD")?;
    let password = percent_encode_base64(&password);
    Ok(format!("postgres://triage_app:{password}@{host}:{port}/{db}"))
}

fn percent_encode_base64(s: &str) -> String {
    s.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D")
}
