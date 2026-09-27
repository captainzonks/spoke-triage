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
//              with the one other Rust module in Spoke. Secrets are
//              returned wrapped in `Secret`, which has no `Display`, a
//              redacting `Debug`, and one named accessor (ADR-026).
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-27
// Version: 0.2.0
// ==============================================================================

use std::fmt;

/// A secret value (password, API key, or a URL embedding one).
///
/// Deliberately has no `Display` and no `Clone`, and its `Debug` prints
/// `Secret([REDACTED])`, so a secret can't reach a log line through `{}` or
/// `{:?}` by accident, including via a struct that derives `Debug`. The
/// value is readable only through `expose()`, which should appear only at
/// the call that actually needs it (a database connect, an auth header).
/// It does not zero its memory on drop (ADR-026).
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Secret(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

pub fn read_secret(file_var: &str, plain_var: &str) -> anyhow::Result<Secret> {
    if let Ok(path) = std::env::var(file_var) {
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("failed to read {file_var}={path}: {e}"))?;
        return Ok(Secret::new(contents.trim().to_string()));
    }
    std::env::var(plain_var)
        .map(Secret::new)
        .map_err(|_| anyhow::anyhow!("either {file_var} or {plain_var} must be set"))
}

/// Builds a `postgres://triage_app:...@host:port/db` URL from Spoke's
/// POSTGRES_HOST/POSTGRES_PORT hub vars, `db_name_var`'s module-specific DB
/// name var, and the triage_app password (read via `read_secret`).
/// Percent-encodes the password: Spoke's secret convention generates
/// passwords with `openssl rand -base64 32`, whose alphabet (`+`, `/`, `=`)
/// is not URL-safe unescaped.
pub fn build_postgres_url(db_name_var: &str) -> anyhow::Result<Secret> {
    let host = std::env::var("POSTGRES_HOST").map_err(|_| anyhow::anyhow!("POSTGRES_HOST must be set"))?;
    let port = std::env::var("POSTGRES_PORT").unwrap_or_else(|_| "5432".to_string());
    let db = std::env::var(db_name_var).map_err(|_| anyhow::anyhow!("{db_name_var} must be set"))?;
    let password = read_secret("TRIAGE_APP_PSQL_PASSWORD_FILE", "TRIAGE_APP_PSQL_PASSWORD")?;
    let password = percent_encode_base64(password.expose());
    Ok(Secret::new(format!("postgres://triage_app:{password}@{host}:{port}/{db}")))
}

fn percent_encode_base64(s: &str) -> String {
    s.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D")
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn debug_does_not_reveal_the_value() {
        let secret = Secret::new("hunter2-not-a-real-password".to_string());
        let shown = format!("{secret:?}");
        assert!(!shown.contains("hunter2"), "{shown}");
        assert_eq!(shown, "Secret([REDACTED])");
    }

    #[test]
    fn debug_of_a_containing_struct_stays_redacted() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            name: &'static str,
            url: Secret,
        }
        let holder = Holder { name: "db", url: Secret::new("postgres://u:s3cr3t@h/db".to_string()) };
        let shown = format!("{holder:#?}");
        assert!(!shown.contains("s3cr3t"), "{shown}");
        assert!(shown.contains("db"));
    }

    #[test]
    fn expose_returns_the_value_unchanged() {
        assert_eq!(Secret::new("abc+/=".to_string()).expose(), "abc+/=");
    }
}
