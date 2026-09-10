# ==============================================================================
# spec.md - spoke-triage design specification
# ==============================================================================
# Description: Spec for spoke-triage, a Rust replacement for
#              spoke_log_analysis.sh's `claude -p` shell-out. Covers the
#              collector/analyst split, normalization-as-redaction,
#              structured output, persistence, suppression loop, cost
#              control, and testing strategy. Implementation gated on
#              approval of this spec plus the ADRs in
#              docs/architecture_decisions.md.
# Author: Matt Barham
# Created: 2026-09-08
# Modified: 2026-09-10
# Version: 0.1.2
# ==============================================================================
# Document Type: Spec
# Audience: Implementers of spoke-triage; reviewers approving before code
# Status: Draft — awaiting approval
# ==============================================================================

## 1. Problem

`spoke/scripts/maintenance/spoke_log_analysis.sh` (471 lines, v1.0.1) does
AI-triaged log analysis today: four Loki `query_range` calls, raw JSON
concatenated into a prompt (truncated at 102400 bytes/query), a `claude -p`
shell-out asked to return JSON in prose, and an HTML report emailed and
discarded. Defects (see build brief `docs/local/spoke_triage_build_prompt.md`
in the `spoke` repo for full rationale): interactive-auth dependency,
unenforced output shape, no persistence, truncation/token waste, static
institutional knowledge, no cost accounting, raw logs leaving the host
unconstrained.

## 1.1 Optimization priority (overrides all other tie-breaks)

Cost/token efficiency is the primary design constraint for this project, not
a secondary nice-to-have — the defect list in §1 exists because the current
script has zero cost accounting and no aggregation, and that gap is the
whole reason spoke-triage exists. When any decision below has a cheaper and
a more-capable option, **default to the cheaper option** unless a concrete
eval shows it fails the evidence-rule bar (§7). Concretely, in priority
order:

1. Aggregate before sending anything to the API (§4) — this is the single
   biggest lever (lines ÷ distinct templates) and is non-negotiable.
2. Suppress `benign`-verdict templates before the API call (§6.1), not after.
3. Default model is the cheapest tier that clears the eval bar — start at
   `claude-haiku-4-5`, do not pre-emptively reach for Sonnet/Opus (§9).
4. No `thinking` param for this task — classification over pre-redacted
   structured input does not need extended/adaptive reasoning; omitting it
   avoids paying for reasoning tokens the task doesn't need. Only add
   `thinking` if eval data shows the cheap model misclassifying severity in
   a way more reasoning would fix — try a bigger model before adding
   reasoning to a small one.
5. `output_config.effort` (if set at all): default `low`. This is a
   structured-output classification call, not agentic work — raise only on
   evidence, not by default.
6. Prompt caching is mandatory, not optional, once the cached block clears
   the minimum token floor (§9) — a static system prompt that isn't cached
   is a standing cost leak.
7. Hard monthly budget (§9) degrades to no-triage-still-emails rather than
   ever silently exceeding budget.

## 2. Non-goals

- Not a general-purpose log aggregation replacement — Loki stays the log
  store; spoke-triage only queries and triages.
- Not a UI. Verdict recording is CLI-first; a full web UI is out of scope.
- Not multi-tenant. Single Spoke deployment, one Postgres role, one report.

## 3. Architecture

Two containers, split on the egress boundary. See
[ADR-015](architecture_decisions.md#adr-015-collectoranalyst-egress-split)
for the full rationale.

### 3.1 `triage-collector` — no egress

Internal network only. Responsibilities:

1. Query Loki (`query_range`, same four severities as the current script:
   `critical_fatal`, `errors`, `warnings`, `system_issues`).
2. Normalize each log line to a template (§4).
3. Aggregate by `template_hash`: count, first_seen, last_seen, contributing
   services, up to N verbatim exemplar lines.
4. Write aggregates to Postgres.
5. Hand off aggregated data (not raw lines) to `triage-analyst` via a shared
   Postgres table — no network call between the two containers.

Never talks to the internet. No Docker socket access.

### 3.2 `triage-analyst` — the only container with egress

Reads aggregated templates + counts + history from Postgres. Calls the
Anthropic Messages API. Never receives raw log lines — only normalized
templates, which are structurally incapable of carrying a secret, IP, or user
identifier (§4). Holds no Docker socket access.

- API key from `/run/secrets/anthropic_api_key`, referenced in compose as
  `ANTHROPIC_API_KEY_FILE=/run/secrets/anthropic_api_key` (custom entrypoint
  reads the file into an env var at container start — no native `_FILE`
  support in the `anthropic` Rust ecosystem, so the entrypoint does what
  Traefik's custom entrypoint already does for `_FILE` vars elsewhere in
  Spoke). Never baked into the image, never a literal env var.
- `cap_drop: ALL`, `read_only: true` root, `no-new-privileges:true`, run as
  `1000:968`, per-service `mem_limit`/`cpus` — matching hub/monitoring
  conventions (`docs/docker_compose_structure_standards.md` in `spoke`).
- Outbound HTTPS restricted to `api.anthropic.com`: an `iptables OUTPUT` rule
  on the container's network namespace, matched by destination IP resolved
  from `api.anthropic.com` at container start and refreshed by a resolver
  sidecar (DNS-backed IPs are not static — do not hardcode). Check
  `spoke-redm` and `spoke-piped` for existing scoped-egress patterns in Spoke
  before inventing a new mechanism; if neither fits, fall back to a
  destination-IP allowlist refreshed on a short interval via cron inside the
  sidecar. Document the refresh cadence and the failure mode (stale IP ⇒
  requests fail closed, not open) in the ADR.

## 4. Normalization (the core of the redaction claim)

Reduce each log line to a template by replacing variable substrings with
typed placeholders, in this order (earlier patterns take priority over
later, more general ones, to avoid e.g. an IP octet being swallowed by a
generic decimal-number pattern):

1. ISO 8601 / RFC 3339 timestamps → `<TIMESTAMP>`
2. UUIDs (v1–v5, any dash format) → `<UUID>`
3. IPv6 addresses → `<IPV6>`
4. IPv4 addresses → `<IPV4>`
5. MAC addresses → `<MAC>`
6. Email addresses → `<EMAIL>`
7. URLs (`scheme://...`) → `<URL>`
8. Absolute file paths (`/...` with ≥2 segments) → `<PATH>`
9. Hex runs ≥8 chars (tokens, hashes, keys) → `<HEX>`
10. PIDs — only when preceded by a PID-indicating label (`pid=`, `PID `,
    `[pid:`) → `<PID>` (bare numbers are not assumed to be PIDs; see the
    evidence-rule carryover in §7)
11. Remaining decimal number runs → `<NUM>`

`template_hash` = SHA-256 of `(service_name, logger_or_module,
normalized_template)` — not template text alone. Two structurally identical
lines from different services/loggers must not collapse to the same hash,
so that an operator marking one template `benign` cannot silently suppress
an unrelated issue elsewhere (see §6).

Two effects follow, and both matter to the design:

- **Cost**: token spend drops by roughly (lines ÷ distinct templates).
  Aggregate before any API call.
- **Redaction as a structural property**: a normalized template cannot carry
  an IP, email, UUID, absolute path, or long hex run — enforced by the
  redaction test suite (§8), not by inspection.

## 5. Structured output

Use Messages API tool-use to force the report shape: define the report as a
tool `input_schema`, force it with `tool_choice: {"type": "tool", "name":
"triage_report"}`, and set `strict: true` on the tool definition
(`additionalProperties: false` + `required`) so `tool_use.input` validates
exactly server-side — no fence-stripping, no empty-output handling.

Preserve the existing severity ladder (CRITICAL/HIGH/MEDIUM/LOW/INFO) and
per-finding fields (service, issue, count, first_seen, last_seen,
recommendation) from the current script, plus the top-level summary,
total_events, and health verdict. Add:

- `template_hash` on every finding, joining back to the collector's data.
- `status: new | recurring | escalating | resolved` — **computed by the
  collector from history, never asked of the model.** The model classifies
  severity; the database decides novelty.

## 6. Persistence

New database + role on the existing `postgres-hub`. Versioned, forward-only
migrations from the first commit (pattern: `GeneGnome/database/`).

```
log_template        (template_hash PK, service_name, logger, template_text,
                      first_seen, last_seen, total_count)
template_occurrence  (id PK, template_hash FK, run_id FK, service_name,
                       count, window_start, window_end)
run                  (id PK, started_at, window_start, window_end,
                       health_verdict, summary, status)
finding              (id PK, run_id FK, template_hash FK, severity, issue,
                       recommendation, status)
verdict              (template_hash PK, classification (benign|known-issue|
                       watch), note, set_by, set_at)
api_call             (id PK, run_id FK, model, input_tokens, output_tokens,
                       cache_write_tokens, cache_read_tokens, latency_ms,
                       estimated_cost_usd)
```

**Role model — do not repeat the GeneGnome mistake.** In GeneGnome the RLS
policies were inert because `POSTGRES_USER` made the application role the
bootstrap superuser, and superusers bypass row security unconditionally.
Create a distinct, non-superuser `triage_app` role explicitly, grant it only
what it needs (`SELECT`/`INSERT`/`UPDATE` on the five tables above, no
`DROP`/`ALTER`), and connect as that role via a `_FILE`-sourced password
(`docs/secrets_support.md` `_FILE` convention — same pattern as
GeneGnome's `POSTGRES_APP_PASSWORD_FILE` after its fix). If row-level
security is added, prove it with a migration test that connects as
`triage_app` and demonstrates a denied read against a row it shouldn't see.

### 6.1 Suppression loop

- Templates with a `benign` verdict are filtered out **before** the API
  call — the cost saving and the noise reduction in one move.
- Templates with `watch` are always sent, with the operator's note as
  context appended to that template's entry in the aggregated payload.
- CLI subcommand to record a verdict without editing files:
  `triage-cli verdict set <template_hash> <benign|known-issue|watch> --note "..."`.
- Seed `verdict` from `spoke/scripts/maintenance/log_analysis_known_patterns.md.example`
  at first migration — parse each `## heading` as a category, prose as the
  note, so the WebSocket-reconnect / DB-disconnect-on-restart / log-shipper
  patterns already documented there survive the migration.

## 7. Evidence rules — carried over verbatim

The current script's system prompt evidence rules (`spoke_log_analysis.sh`
lines 229–253) must be preserved word-for-word in the new system prompt.
Quoting them here so the implementer copies from this spec, not by re-typing
from the shell script (transcription risk):

> ## Evidence Rules (CRITICAL - read before writing any finding)
>
> Every finding must be traceable to raw log lines present below. Specifically:
>
> - **Quote before claiming.** For any claim of a process signal, crash,
>   shutdown, restart, OOM, or worker recycling, the `issue` field must
>   include a verbatim fragment (>= 20 chars) from an actual log line that
>   contains one of these explicit keywords: `SIGINT`, `SIGTERM`, `SIGKILL`,
>   `SIGSEGV`, `SIGABRT`, `Received signal`, `forwarding signal`, `Out of
>   memory`, `oom-killer`, `Killed process`, `segfault`, `core dumped`,
>   `panic:`, `Shutting down`, `Stopping worker`, or `Worker <id> stopped`.
>   If no such line is present in the data below, do not produce the finding.
> - **Do NOT infer from PIDs.** PID values are not evidence. High PID
>   numbers, sequential PID numbers, or multiple distinct PIDs do NOT
>   constitute worker recycling, churn, or signals. Report such things only
>   when an explicit signal/shutdown line exists.
> - **Framework "signals" ≠ Unix signals.** Log lines mentioning
>   Django-style `signals` modules (e.g. `authentik.X.signals`, logger names
>   ending in `.signals`, "Imported related module ... signals") are
>   framework pub/sub imports. Never report these as SIGINT/SIGTERM/SIGKILL
>   events.
> - **Timestamps and PIDs must be verbatim.** Every `first_seen`,
>   `last_seen`, `count`, and any PID you cite must come from the raw data.
>   Do not estimate, interpolate, or synthesize values.
> - **Prefer omission over fabrication.** If the data does not clearly
>   support a finding, leave it out. An empty section is better than an
>   invented one.

One adaptation is required: the rules above were written for raw log lines;
`triage-analyst` sends normalized templates + exemplar lines instead. The
"verbatim fragment" requirement still applies against the exemplar lines
retained locally in Postgres (§3.1) — the model quotes from what it's given,
which is now templates-plus-exemplars rather than raw Loki output. Do not
loosen the requirement; adapt only the phrase "raw log lines present below"
to describe the new input shape.

## 8. Testing

- **Redaction suite (mandatory, property-based where practical).** Assert no
  normalized template retains an IP, email, UUID, absolute path, bearer
  token, or long hex run. This is the security claim of the whole design.
- **Golden tests for normalization** — corpus of real log lines in, expected
  templates out. Seed from exemplars already flowing through
  `spoke_log_analysis.sh` today plus the patterns in
  `log_analysis_known_patterns.md.example`.
- **Mocked API transport** — trait-based client, mock in tests, so the suite
  never makes a paid Anthropic call.
- **Migration tests** — apply from empty, verify `triage_app`'s grants,
  verify a denied read if RLS is used.
- **End-to-end dry-run mode** — query, normalize, aggregate, render, skip the
  API call and the mail send, print what would have happened.

## 9. Model and cost control

Recommended model: **`claude-haiku-4-5`** (`$1`/`$5` per MTok in/out as of
2026-09-08 — verify live before locking, per §11). Rationale: triage input is
pre-aggregated, structurally-redacted templates with counts — a
classification-shaped task, not open-ended reasoning. Haiku 4.5 is the
cheapest tier and the evidence-rule-constrained, schema-forced output leaves
little room for the kind of judgment calls that would justify Sonnet-tier
cost. Escalate to `claude-sonnet-5` only if eval data shows Haiku
under-classifying severity on real Spoke logs.

- Prompt caching on the static system prompt (evidence rules, ~1KB, cheap to
  cache — but Haiku 4.5's minimum cacheable prefix per the cached model
  table is 4096 tokens; **verify the evidence-rule block plus schema
  actually clears that floor before relying on cache savings**, or bundle
  additional stable content — e.g. the full known-patterns seed text — into
  the cached block to clear the minimum).
- Record `input_tokens`, `output_tokens`, `cache_creation_input_tokens`,
  `cache_read_input_tokens`, and an estimated cost per run in `api_call`.
- Configurable monthly budget, default **$20/month** via
  `TRIAGE_MONTHLY_BUDGET_USD`. When exhausted, the run still completes and
  still emails — aggregation and history, no model triage — and says so
  plainly. Degrade, never fail silently.
- Exponential backoff with jitter on 429 and 5xx, bounded retry count,
  honoring the `retry-after` header when present.

## 10. Reporting

1. **Email** through the existing mail relay, preserving the current HTML
   report's structure. Add the new-vs-recurring signal (from `finding.status`)
   and a cost line (from `api_call`).
2. **Grafana dashboard**, committed as JSON in this repo under
   `grafana/dashboards/`, provisioned into `spoke-monitoring`'s Grafana via a
   provisioning directory mount — see
   [ADR-018](architecture_decisions.md#adr-018-grafana-dashboard-provisioning-lives-in-spoke-triage).
   Panels: findings by severity over time, top recurring templates, new
   templates in the window, token spend and cost trend, run health history.

## 11. Anthropic API surface — verify before implementation

As of this writing (2026-09-08), confirmed live against `docs.claude.com`:
current models are `claude-opus-5`, `claude-sonnet-5` ($2/$10 per MTok),
`claude-haiku-4-5-20251001` ($1/$5), `claude-fable-5-1` ($10/$50). Cache
read = 10% of base input price. **Not yet confirmed live**: cache-write
multiplier and exact minimum-cacheable-token-count for Haiku 4.5 at
implementation time (cached guidance says 4096 tokens/1.25x-2x write, but
this drifted once already during spec-writing — re-check
`docs.claude.com` immediately before writing the Rust client, not from this
spec). No official Anthropic Rust SDK exists — use `reqwest` + `serde_json`
against the documented JSON wire shapes (`x-api-key` header,
`anthropic-version: 2023-06-01`, `POST /v1/messages`).

## 12. Deliverables (from build brief, unchanged)

1. This spec + the ADRs, approved, before implementation.
2. `spoke-triage` repository (this one), public, standalone-first (ADR-008
   pattern from `spoke`), README that stands alone.
3. Migrations, tests, provisioned Grafana dashboard JSON.
4. systemd unit + timer (harden per §13).
5. Deprecation note for `spoke_log_analysis.sh` in the `spoke` repo — keep it
   working, document supersession.

## 13. systemd

Copy `crowdsec_weekly_summary.service`/`.timer` from `spoke`'s
`scripts/maintenance/` verbatim for the hardening baseline:

```
PrivateTmp=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/tmp
```

`Type=oneshot`, Docker-readiness `ExecStartPre` poll, `journal` logging,
timer with jitter (`RandomizedDelaySec`).

## 14. Conventions checklist

- Header block on every file: 78-char `=` rules, filename + one-line
  summary, Description, Author (Matt Barham), Created/Modified (ISO 8601),
  Version (new files start 0.1.0). Docs add Document Type/Audience/Status.
- snake_case filenames, underscores not hyphens.
- `docker-compose.yml` section order: header → name → EXTENSIONS →
  NETWORKS → VOLUMES → SECRETS → SERVICES (per
  `docs/docker_compose_structure_standards.md` in `spoke`), `VAR=${VAR}`
  format, no quotes on ports/IPs.
- `modules.yml.example` registration entry with `repo`, `ref`, `enabled`,
  `env_overrides`, `secrets_map` — mirror the monitoring module's entry.
- ADR numbering continues from `spoke`'s highest existing ADR at the time of
  writing — this repo's ADRs are ADR-015+, kept in this repo's own
  `docs/architecture_decisions.md` since spoke-triage is standalone-first,
  cross-referenced from `spoke`'s ADR log rather than merged into it. (This
  repo originally claimed ADR-013+, colliding with two ADRs `spoke` had
  added to its own sequence in the meantime — see `spoke`'s own
  `docs/module_development.md` for the convention that should prevent a
  repeat.)
