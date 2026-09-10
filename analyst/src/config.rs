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
//              _FILE handling and needs no extra image layer).
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-09
// Version: 0.1.0
// ==============================================================================

use spoke_triage_common::secret::read_secret;

pub struct Config {
    pub database_url: String,
    pub anthropic_api_key: String,
    pub model: String,
    pub monthly_budget_usd: f64,
    pub known_patterns_path: Option<String>,
    pub max_tokens: u32,
    // Safety valve for spec §5's single-call design: on a cold verdict table
    // (first run, or after a diverse-log day) benign suppression alone
    // doesn't bound template count, and an unbounded prompt can blow past
    // the model's 200K-token context (observed: 2129 templates -> 1.65M
    // tokens on a real Spoke deployment's first live run). Cap to the
    // highest-count templates
    // — those carry the most log volume — and let the long tail roll to
    // next run, where by-then-classified verdicts will have suppressed the
    // noisy ones. Not token-exact since exemplar/template_text length
    // varies; 150 is sized off that first run's ~775 tokens/template
    // average with headroom under 200K for system prompt + schema.
    pub max_templates_per_run: i64,
    pub instance_name: String,
    pub lookback_hours: i64,
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
            database_url: spoke_triage_common::secret::build_postgres_url("TRIAGE_POSTGRES_DB")?,
            anthropic_api_key: read_secret("ANTHROPIC_API_KEY_FILE", "ANTHROPIC_API_KEY")?,
            model: env_or("TRIAGE_MODEL", "claude-haiku-4-5"),
            monthly_budget_usd: env_or("TRIAGE_MONTHLY_BUDGET_USD", "20").parse()?,
            known_patterns_path: std::env::var("TRIAGE_KNOWN_PATTERNS_PATH").ok(),
            max_tokens: env_or("TRIAGE_MAX_TOKENS", "4096").parse()?,
            max_templates_per_run: env_or("TRIAGE_MAX_TEMPLATES_PER_RUN", "150").parse()?,
            instance_name: env_or("INSTANCE_NAME", "spoke"),
            lookback_hours: env_or("TRIAGE_LOOKBACK_HOURS", "24").parse()?,
            mail_relay_host: env_or("TRIAGE_MAIL_RELAY_HOST", "mail-relay"),
            mail_relay_port: env_or("TRIAGE_MAIL_RELAY_PORT", "8000").parse()?,
            mail_to: std::env::var("TRIAGE_MAIL_TO").ok().filter(|s| !s.is_empty()),
        })
    }
}

fn env_or(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}
