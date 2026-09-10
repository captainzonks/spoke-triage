-- ==============================================================================
-- 0001_initial_schema.sql - spoke-triage initial schema
-- ==============================================================================
-- Description: First migration. Creates the six tables from docs/spec.md §6
--              (run, log_template, template_occurrence, verdict, finding,
--              api_call) plus indexes and triage_app grants.
-- Author: Matt Barham
-- Created: 2026-09-09
-- Modified: 2026-09-10
-- Version: 0.1.1
-- ==============================================================================
--
-- Role model (docs/spec.md §6): this migration is applied by the `triage_app`
-- role provisioned via scripts/modules/provision_hub_postgres.sh (declared in
-- this repo's stack.yml, matching the trek/genetics pattern already in use
-- elsewhere in Spoke). triage_app therefore owns the tables it creates here.
--
-- Caveat carried over from that same pattern (and already accepted for
-- spoke-genetics): PostgreSQL always lets an object's owner ALTER/DROP it,
-- regardless of REVOKE. The explicit per-table GRANTs below are the real
-- guardrail against DROP/ALTER, not a Postgres-enforced one: no application
-- code path in triage-collector or triage-analyst issues DDL, and both
-- connect over parameterized sqlx queries, so DROP/ALTER is unreachable in
-- practice even though the role technically has the privilege. A hard
-- Postgres-level lockout would require splitting DB ownership from the
-- runtime role, which provision_hub_postgres.sh does not currently support
-- (see spoke-triage docs/architecture_decisions.md if this gets revisited).
--
-- One deviation from the six-table list in spec §6: `template_occurrence`
-- gains an `exemplar_lines TEXT[]` column. The spec's schema block doesn't
-- list a column for the "up to N verbatim exemplar lines" required by the
-- evidence rules (§7), and there is nowhere else in the six tables to put
-- them — occurrences are the natural per-run-window home for them.
-- ==============================================================================

-- ==============================================================================
-- RUN
-- ==============================================================================

CREATE TABLE run (
    id             BIGSERIAL PRIMARY KEY,
    started_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    window_start   TIMESTAMPTZ NOT NULL,
    window_end     TIMESTAMPTZ NOT NULL,
    health_verdict TEXT CHECK (health_verdict IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    summary        TEXT,
    status         TEXT NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending', 'running', 'completed', 'failed', 'budget_exhausted')),
    CHECK (window_end >= window_start)
);

CREATE INDEX idx_run_started_at ON run (started_at DESC);

COMMENT ON TABLE run IS 'One triage pass over a Loki query window.';
COMMENT ON COLUMN run.status IS 'budget_exhausted = aggregation/history completed, model triage skipped (spec §9).';

-- ==============================================================================
-- LOG_TEMPLATE
-- ==============================================================================

CREATE TABLE log_template (
    template_hash TEXT PRIMARY KEY CHECK (char_length(template_hash) = 64),
    service_name  TEXT NOT NULL,
    logger        TEXT NOT NULL,
    template_text TEXT NOT NULL,
    first_seen    TIMESTAMPTZ NOT NULL,
    last_seen     TIMESTAMPTZ NOT NULL,
    total_count   BIGINT NOT NULL DEFAULT 0 CHECK (total_count >= 0),
    CHECK (last_seen >= first_seen)
);

CREATE INDEX idx_log_template_service_name ON log_template (service_name);
CREATE INDEX idx_log_template_last_seen ON log_template (last_seen DESC);

COMMENT ON TABLE log_template IS 'Normalized template per (service, logger, template) tuple (spec §4). template_hash = SHA-256 of that tuple.';

-- ==============================================================================
-- TEMPLATE_OCCURRENCE
-- ==============================================================================

CREATE TABLE template_occurrence (
    id             BIGSERIAL PRIMARY KEY,
    template_hash  TEXT NOT NULL REFERENCES log_template (template_hash),
    run_id         BIGINT NOT NULL REFERENCES run (id),
    service_name   TEXT NOT NULL,
    count          BIGINT NOT NULL CHECK (count >= 0),
    window_start   TIMESTAMPTZ NOT NULL,
    window_end     TIMESTAMPTZ NOT NULL,
    exemplar_lines TEXT[] NOT NULL DEFAULT '{}',
    CHECK (window_end >= window_start)
);

CREATE INDEX idx_template_occurrence_template_hash ON template_occurrence (template_hash);
CREATE INDEX idx_template_occurrence_run_id ON template_occurrence (run_id);
CREATE INDEX idx_template_occurrence_window ON template_occurrence (window_start, window_end);

COMMENT ON TABLE template_occurrence IS 'Per-run-window aggregate for a template: count plus up to N verbatim exemplar lines for evidence-rule citation (spec §7).';

-- ==============================================================================
-- VERDICT
-- ==============================================================================

-- No FK to log_template: operators may set a verdict for a template that has
-- not been observed yet (proactive suppression seeded from institutional
-- knowledge), so template_hash here must not require a prior log_template row.
CREATE TABLE verdict (
    template_hash  TEXT PRIMARY KEY,
    classification TEXT NOT NULL CHECK (classification IN ('benign', 'known-issue', 'watch')),
    note           TEXT,
    set_by         TEXT NOT NULL,
    set_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE verdict IS 'Operator-set suppression/context per template_hash (spec §6.1). benign is filtered out before the API call.';

-- ==============================================================================
-- FINDING
-- ==============================================================================

CREATE TABLE finding (
    id             BIGSERIAL PRIMARY KEY,
    run_id         BIGINT NOT NULL REFERENCES run (id),
    template_hash  TEXT NOT NULL REFERENCES log_template (template_hash),
    severity       TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    issue          TEXT NOT NULL,
    recommendation TEXT,
    status         TEXT NOT NULL CHECK (status IN ('new', 'recurring', 'escalating', 'resolved'))
);

CREATE INDEX idx_finding_run_id ON finding (run_id);
CREATE INDEX idx_finding_template_hash ON finding (template_hash);
CREATE INDEX idx_finding_severity ON finding (severity);

COMMENT ON COLUMN finding.status IS 'Computed by the collector from history, never asked of the model (spec §5).';

-- ==============================================================================
-- API_CALL
-- ==============================================================================

CREATE TABLE api_call (
    id                  BIGSERIAL PRIMARY KEY,
    run_id              BIGINT NOT NULL REFERENCES run (id),
    model               TEXT NOT NULL,
    input_tokens        BIGINT NOT NULL CHECK (input_tokens >= 0),
    output_tokens       BIGINT NOT NULL CHECK (output_tokens >= 0),
    cache_write_tokens  BIGINT NOT NULL DEFAULT 0 CHECK (cache_write_tokens >= 0),
    cache_read_tokens   BIGINT NOT NULL DEFAULT 0 CHECK (cache_read_tokens >= 0),
    latency_ms          INTEGER NOT NULL CHECK (latency_ms >= 0),
    estimated_cost_usd  NUMERIC(10, 6) NOT NULL CHECK (estimated_cost_usd >= 0),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_api_call_run_id ON api_call (run_id);

COMMENT ON TABLE api_call IS 'One row per Anthropic Messages API call, for cost accounting and the monthly budget gate (spec §9).';

-- ==============================================================================
-- GRANTS (triage_app; see role-model caveat in the file header)
-- ==============================================================================
--
-- This migration runs as triage_app, which then owns every table it just
-- created — so every GRANT below is currently a self-grant and a no-op:
-- Postgres lets an owner SELECT/INSERT/UPDATE/DELETE regardless of what's
-- granted or revoked. They are left in anyway as executable documentation
-- of the intended runtime privilege set (SELECT/INSERT/UPDATE, no DELETE),
-- so that if ownership is ever split from the runtime role — the same
-- prerequisite the DROP/ALTER caveat above already needs — these grants
-- start being the real enforcement instead of a statement of intent.

GRANT SELECT, INSERT, UPDATE ON run TO triage_app;
GRANT SELECT, INSERT, UPDATE ON log_template TO triage_app;
GRANT SELECT, INSERT, UPDATE ON template_occurrence TO triage_app;
GRANT SELECT, INSERT, UPDATE ON verdict TO triage_app;
GRANT SELECT, INSERT, UPDATE ON finding TO triage_app;
GRANT SELECT, INSERT, UPDATE ON api_call TO triage_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO triage_app;
