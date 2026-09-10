// ==============================================================================
// main.rs - triage-analyst entrypoint
// ==============================================================================
// Description: The only-egress side of spoke-triage (docs/spec.md §3.2).
//              Reads aggregated templates from Postgres, calls the Anthropic
//              Messages API with forced structured output, records cost, and
//              writes findings. Never receives raw log lines.
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-10
// Version: 0.1.1
// ==============================================================================

mod anthropic;
mod config;
mod cost;
mod db;
mod mail;
mod prompt;
mod report;
mod report_render;
mod schema;

use anthropic::{AnthropicTransport, CacheControl, MessageParam, MessagesRequest, SystemBlock, ToolChoice, Transport};
use config::Config;
use mail::{MailTransport, RelayTransport, SendRequest};
use report_render::ReportContext;
use sqlx::postgres::PgPoolOptions;
use std::time::Instant;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::from_env()?;
    // Spec §8: "render ... skip the API call and the mail send, print what
    // would have happened." Reads (next_pending_run, load_pending_templates,
    // month_to_date_spend_usd) still run for real — they're the boundary
    // already crossed by triage-collector — but every write and the
    // Anthropic/mail calls are replaced with a printed preview so a dry run
    // leaves the real pending run untouched for a later real run to process.
    let dry_run = std::env::args().any(|a| a == "--dry-run");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&cfg.database_url)
        .await?;

    let Some(pending) = db::next_pending_run(&pool).await? else {
        eprintln!("no pending run");
        return Ok(());
    };
    let run_id = pending.run_id;
    eprintln!("run {run_id}: analyzing window {} .. {}", pending.window_start, pending.window_end);

    let mail_transport = RelayTransport::new(&cfg.mail_relay_host, cfg.mail_relay_port);

    // Hard monthly budget gate (spec §9/§1.1 point 7): degrade to
    // aggregation-and-history-only rather than silently exceeding budget —
    // and still email, saying so plainly, per spec §9's "degrade, never
    // fail silently".
    let spend = db::month_to_date_spend_usd(&pool).await?;
    if spend >= cfg.monthly_budget_usd {
        eprintln!("month-to-date spend ${spend:.2} >= budget ${:.2} — skipping model triage", cfg.monthly_budget_usd);
        let ctx = ReportContext {
            instance_name: &cfg.instance_name,
            lookback_hours: cfg.lookback_hours,
            health: "unknown",
            total_events: 0,
            summary: "Monthly budget exhausted — AI triage skipped this run. Aggregation and history are still current; no severity classification was performed.",
            findings: &[],
            model: &cfg.model,
            run_cost_usd: 0.0,
            month_to_date_usd: spend,
            monthly_budget_usd: cfg.monthly_budget_usd,
            generated_at: chrono::Utc::now(),
        };
        if dry_run {
            println!("=== DRY RUN — run {run_id} — budget exhausted — no Postgres writes, no mail sent ===");
            println!("{}", report_render::build_text(&ctx));
        } else {
            db::mark_run_status(&pool, run_id, "budget_exhausted").await?;
            send_report(&mail_transport, &cfg, ctx).await;
        }
        return Ok(());
    }

    let templates = db::load_pending_templates(&pool, run_id, cfg.max_templates_per_run).await?;
    if templates.is_empty() {
        eprintln!("no non-benign templates this run");
        if dry_run {
            println!("=== DRY RUN — run {run_id} — no non-benign templates — no Postgres write ===");
        } else {
            db::mark_run_status(&pool, run_id, "completed").await?;
        }
        return Ok(());
    }
    eprintln!("{} templates after benign suppression", templates.len());

    if dry_run {
        let system_text = prompt::build_system_prompt(known_patterns_ref(&cfg).as_deref());
        let user_text = prompt::build_user_message(&templates);
        println!("=== DRY RUN — run {run_id} — {} templates — no Anthropic call, no mail sent ===", templates.len());
        println!("model: {}  max_tokens: {}  system_prompt: {} chars  user_message: {} chars", cfg.model, cfg.max_tokens, system_text.len(), user_text.len());
        println!("--- user message that would be sent ---");
        println!("{user_text}");
        let ctx = ReportContext {
            instance_name: &cfg.instance_name,
            lookback_hours: cfg.lookback_hours,
            health: "unknown",
            total_events: templates.iter().map(|t| t.total_count).sum(),
            summary: "DRY RUN — Anthropic was not called, so no severity classification is shown here. See the user message above for exactly what would have been sent.",
            findings: &[],
            model: &cfg.model,
            run_cost_usd: 0.0,
            month_to_date_usd: spend,
            monthly_budget_usd: cfg.monthly_budget_usd,
            generated_at: chrono::Utc::now(),
        };
        println!("--- email that would be sent to {} ---", cfg.mail_to.as_deref().unwrap_or("(TRIAGE_MAIL_TO unset — would skip)"));
        println!("{}", report_render::build_text(&ctx));
        return Ok(());
    }

    let transport = AnthropicTransport::new(cfg.anthropic_api_key.clone());
    match run_analysis(&transport, &cfg, &templates).await {
        Ok((report, usage, latency_ms)) => {
            let cost = cost::estimate_cost_usd(
                &cfg.model,
                usage.input_tokens,
                usage.output_tokens,
                usage.cache_creation_input_tokens,
                usage.cache_read_input_tokens,
            );
            db::record_api_call(
                &pool,
                run_id,
                &cfg.model,
                usage.input_tokens,
                usage.output_tokens,
                usage.cache_creation_input_tokens,
                usage.cache_read_input_tokens,
                latency_ms,
                cost,
            )
            .await?;
            eprintln!(
                "usage: {} in / {} out / {} cache-write / {} cache-read (${cost:.4})",
                usage.input_tokens, usage.output_tokens, usage.cache_creation_input_tokens, usage.cache_read_input_tokens
            );

            db::write_run_summary(&pool, run_id, &report.health, &report.summary, report.total_events).await?;
            let health = report.health.clone();
            let summary = report.summary.clone();
            let total_events = report.total_events;
            let scored = report.into_scored_findings();
            eprintln!("{} findings", scored.len());
            let written = db::write_findings(&pool, run_id, &scored).await?;
            db::mark_run_status(&pool, run_id, "completed").await?;

            send_report(
                &mail_transport,
                &cfg,
                ReportContext {
                    instance_name: &cfg.instance_name,
                    lookback_hours: cfg.lookback_hours,
                    health: &health,
                    total_events,
                    summary: &summary,
                    findings: &written,
                    model: &cfg.model,
                    run_cost_usd: cost,
                    month_to_date_usd: spend + cost,
                    monthly_budget_usd: cfg.monthly_budget_usd,
                    generated_at: chrono::Utc::now(),
                },
            )
            .await;
        }
        Err(err) => {
            eprintln!("analysis failed: {err}");
            db::mark_run_status(&pool, run_id, "failed").await.ok();
            return Err(err);
        }
    }

    Ok(())
}

async fn run_analysis(
    transport: &dyn Transport,
    cfg: &Config,
    templates: &[db::PendingTemplate],
) -> anyhow::Result<(report::Report, anthropic::Usage, i32)> {
    let system_text = prompt::build_system_prompt(known_patterns_ref(cfg).as_deref());
    let user_text = prompt::build_user_message(templates);

    let request = MessagesRequest {
        model: cfg.model.clone(),
        max_tokens: cfg.max_tokens,
        // Cache the system block once it clears the per-model minimum
        // cacheable-token floor (spec §9/§1.1 point 6); below that floor
        // Anthropic just serves it uncached, so this is safe to always set.
        system: vec![SystemBlock {
            block_type: "text",
            text: system_text,
            cache_control: Some(CacheControl { control_type: "ephemeral" }),
        }],
        messages: vec![MessageParam { role: "user", content: user_text }],
        tools: vec![schema::triage_report_tool()],
        tool_choice: ToolChoice::Tool { name: schema::TRIAGE_REPORT_TOOL_NAME.to_string() },
    };

    let started = Instant::now();
    let response = transport.create_message(&request).await?;
    let latency_ms = started.elapsed().as_millis() as i32;

    let report = report::parse_report(&response)?;
    Ok((report, response.usage, latency_ms))
}

/// Best-effort: a mail relay outage shouldn't mark an otherwise-successful
/// triage run as failed. Findings are already durably in Postgres by the
/// time this is called; email is a convenience delivery, not the record.
async fn send_report(transport: &dyn MailTransport, cfg: &Config, ctx: ReportContext<'_>) {
    let Some(to) = cfg.mail_to.as_deref() else {
        eprintln!("TRIAGE_MAIL_TO not set — skipping email, findings remain in Postgres");
        return;
    };

    let subject = format!("[{}] Daily Log Report - {}", cfg.instance_name, ctx.generated_at.format("%Y-%m-%d"));
    let req = SendRequest {
        to: to.to_string(),
        subject,
        body_text: report_render::build_text(&ctx),
        body_html: report_render::build_html(&ctx),
    };

    match transport.send(&req).await {
        Ok(()) => eprintln!("report emailed to {to}"),
        Err(err) => eprintln!("mail relay send failed (findings still in Postgres): {err}"),
    }
}

fn known_patterns_ref(cfg: &Config) -> Option<String> {
    cfg.known_patterns_path
        .as_deref()
        .and_then(|path| std::fs::read_to_string(path).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anthropic::mock::MockTransport;
    use anthropic::{ContentBlock, MessagesResponse, Usage};
    use chrono::Utc;
    use db::PendingTemplate;
    use serde_json::json;

    fn test_config() -> Config {
        Config {
            database_url: String::new(),
            anthropic_api_key: "test-key".to_string(),
            model: "claude-haiku-4-5".to_string(),
            monthly_budget_usd: 20.0,
            known_patterns_path: None,
            max_tokens: 4096,
            max_templates_per_run: 150,
            instance_name: "spoke".to_string(),
            lookback_hours: 24,
            mail_relay_host: "mail-relay".to_string(),
            mail_relay_port: 8000,
            mail_to: Some("admin@example.test".to_string()),
        }
    }

    fn test_template(hash: &str) -> PendingTemplate {
        PendingTemplate {
            template_hash: hash.to_string(),
            service_name: "plex".to_string(),
            logger: "app".to_string(),
            template_text: "worker <NUM> exited".to_string(),
            total_count: 5,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            exemplar_lines: vec!["worker 42 exited".to_string()],
            verdict_classification: None,
            verdict_note: None,
        }
    }

    /// Spec §8: the mocked transport proves the pipeline end-to-end (prompt
    /// -> forced tool call -> parsed report -> usage) without ever making a
    /// paid Anthropic call, and lets us assert on exactly what was sent.
    #[tokio::test]
    async fn run_analysis_sends_forced_tool_choice_and_parses_the_report() {
        let mock = MockTransport::new(MessagesResponse {
            content: vec![ContentBlock::ToolUse {
                name: schema::TRIAGE_REPORT_TOOL_NAME.to_string(),
                input: json!({
                    "summary": "one recurring worker exit",
                    "total_events": 5,
                    "health": "degraded",
                    "findings": [{
                        "template_hash": "a".repeat(64),
                        "severity": "LOW",
                        "service": "plex",
                        "issue": "worker exited: \"worker 42 exited\"",
                        "count": 5,
                        "first_seen": "2026-09-09T00:00:00Z",
                        "last_seen": "2026-09-09T01:00:00Z",
                        "recommendation": ""
                    }]
                }),
            }],
            usage: Usage {
                input_tokens: 5000,
                output_tokens: 200,
                cache_creation_input_tokens: 4200,
                cache_read_input_tokens: 0,
            },
        });

        let cfg = test_config();
        let templates = vec![test_template(&"a".repeat(64))];

        let (report, usage, _latency_ms) = run_analysis(&mock, &cfg, &templates).await.unwrap();

        assert_eq!(report.health, "degraded");
        assert_eq!(report.total_events, 5);
        assert_eq!(usage.input_tokens, 5000);

        let sent = mock.requests.lock().unwrap();
        assert_eq!(sent.len(), 1);
        match &sent[0].tool_choice {
            ToolChoice::Tool { name } => assert_eq!(name, schema::TRIAGE_REPORT_TOOL_NAME),
        }
        assert_eq!(sent[0].tools.len(), 1);
        assert!(sent[0].system[0].cache_control.is_some());
        assert!(sent[0].messages[0].content.contains(&"a".repeat(64)));
    }

    #[tokio::test]
    async fn run_analysis_errors_when_model_returns_no_tool_use() {
        let mock = MockTransport::new(MessagesResponse {
            content: vec![ContentBlock::Text { text: "I refuse to call the tool.".to_string() }],
            usage: Usage::default(),
        });

        let cfg = test_config();
        let templates = vec![test_template(&"b".repeat(64))];

        assert!(run_analysis(&mock, &cfg, &templates).await.is_err());
    }

    #[tokio::test]
    async fn send_report_skips_when_mail_to_unset() {
        let mock = mail::mock::MockMailTransport::new();
        let mut cfg = test_config();
        cfg.mail_to = None;
        send_report(&mock, &cfg, test_report_ctx()).await;
        assert!(mock.sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn send_report_sends_when_mail_to_set() {
        let mock = mail::mock::MockMailTransport::new();
        let cfg = test_config();
        send_report(&mock, &cfg, test_report_ctx()).await;
        let sent = mock.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, "admin@example.test");
    }

    #[tokio::test]
    async fn send_report_does_not_panic_on_relay_failure() {
        let mock = mail::mock::MockMailTransport::failing();
        let cfg = test_config();
        send_report(&mock, &cfg, test_report_ctx()).await;
    }

    fn test_report_ctx() -> ReportContext<'static> {
        ReportContext {
            instance_name: "spoke",
            lookback_hours: 24,
            health: "degraded",
            total_events: 5,
            summary: "test summary",
            findings: &[],
            model: "claude-haiku-4-5",
            run_cost_usd: 0.01,
            month_to_date_usd: 1.0,
            monthly_budget_usd: 20.0,
            generated_at: chrono::Utc::now(),
        }
    }
}
