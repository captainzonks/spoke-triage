// ==============================================================================
// config.rs - triage-analyst environment configuration
// ==============================================================================
// Description: Env-var-driven config. DATABASE_URL is built from
//              POSTGRES_HOST/POSTGRES_PORT/TRIAGE_POSTGRES_DB plus the
//              triage_app password (spec §6 role model). ANTHROPIC_API_KEY
//              is read from ANTHROPIC_API_KEY_FILE via
//              spoke_triage_common::secret — read natively in Rust rather
//              than a shell entrypoint (spec §3.2 speculated the latter
//              before this existed; native reading matches spoke-trek's own
//              _FILE handling and needs no extra image layer). Both
//              secrets live in `Secrets`, not `Config`, so nothing that logs
//              settings can reach them (ADR-026).
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-27
// Version: 0.2.0
// ==============================================================================

use spoke_triage_common::secret::{read_secret, Secret};

/// Credentials only. Kept apart from `Config` so the ordinary settings can be
/// logged or passed around freely (ADR-026).
#[derive(Debug)]
pub struct Secrets {
    pub database_url: Secret,
    pub anthropic_api_key: Secret,
}

impl Secrets {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Secrets {
            database_url: spoke_triage_common::secret::build_postgres_url("TRIAGE_POSTGRES_DB")?,
            anthropic_api_key: read_secret("ANTHROPIC_API_KEY_FILE", "ANTHROPIC_API_KEY")?,
        })
    }
}

pub struct Config {
    pub model: String,
    pub monthly_budget_usd: f64,
    pub known_patterns_path: Option<String>,
    pub max_tokens: u32,
    // Safety valve for spec §5's single-call design: on a cold verdict table
    // (first run, or after a diverse-log day) benign suppression alone
    // doesn't bound template count, and an unbounded prompt can blow past
    // the model's 200K-token context (observed: 2129 templates -> 1.65M
    // tokens on a real Spoke deployment's first live run). The cap keeps
    // templates new this window first, then this window's highest counts
    // (db::select_for_prompt). Templates past the cap are NOT carried over:
    // occurrences are per-run, so they only reappear if they recur — the
    // analyst logs how many were cut each run. Not token-exact since exemplar/template_text length
    // varies; 150 is sized off that first run's ~775 tokens/template
    // average with headroom under 200K for system prompt + schema.
    pub max_templates_per_run: i64,
    pub instance_name: String,
    // Host+port rather than a single URL: triage-egress-guard (which shares
    // this container's netns) needs a bare hostname to `dig`, so keeping
    // the same shape here avoids parsing a URL apart just to reassemble it.
    pub mail_relay_host: String,
    pub mail_relay_port: u16,
    pub mail_to: Option<String>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Config {
            model: env_or("TRIAGE_MODEL", "claude-haiku-4-5"),
            monthly_budget_usd: env_or("TRIAGE_MONTHLY_BUDGET_USD", "20").parse()?,
            known_patterns_path: std::env::var("TRIAGE_KNOWN_PATTERNS_PATH").ok(),
            max_tokens: env_or("TRIAGE_MAX_TOKENS", "4096").parse()?,
            max_templates_per_run: env_or("TRIAGE_MAX_TEMPLATES_PER_RUN", "150").parse()?,
            instance_name: env_or("INSTANCE_NAME", "spoke"),
            mail_relay_host: env_or("TRIAGE_MAIL_RELAY_HOST", "mail-relay"),
            mail_relay_port: env_or("TRIAGE_MAIL_RELAY_PORT", "8000").parse()?,
            mail_to: std::env::var("TRIAGE_MAIL_TO").ok().filter(|s| !s.is_empty()),
        })
    }
}

fn env_or(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::Secrets;
    use spoke_triage_common::secret::Secret;

    #[test]
    fn secrets_debug_redacts_both_values() {
        let secrets = Secrets {
            database_url: Secret::new("postgres://triage_app:pw-in-url@db:5432/triage".to_string()),
            anthropic_api_key: Secret::new("sk-ant-not-a-real-key".to_string()),
        };
        let shown = format!("{secrets:?}");
        assert!(!shown.contains("pw-in-url"), "{shown}");
        assert!(!shown.contains("sk-ant"), "{shown}");
    }
}
