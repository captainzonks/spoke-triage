# spoke-triage

<!--
==============================================================================
README.md - spoke-triage module documentation
==============================================================================
Description: AI-triaged Loki log analysis — aggregate, normalize/redact,
             classify, persist, report, track cost
Author: Matt Barham
Created: 2026-09-09
Modified: 2026-09-10
Version: 0.1.2
==============================================================================
Document Type: Reference
Audience: Developer
Status: Final
==============================================================================
-->

AI-triaged log analysis for Loki, in Rust. Queries the last N hours of
`critical_fatal`/`errors`/`warnings`/`system_issues` logs, collapses them to
structurally-redacted templates, sends only the aggregates to Claude for
classification, persists everything to Postgres, and emails an HTML report
with a cost line. Replaces `spoke_log_analysis.sh` from the parent
[Spoke](https://github.com/captainzonks/spoke) platform's
`scripts/maintenance/` — see [Why this exists](#why-this-exists) for what
that script got wrong.

The module is **standalone** — it makes no assumptions about which other
Spoke modules you have deployed beyond a running Loki instance to query.
Site-specific behavior (institutional knowledge, mail recipient, cost
budget, model choice) is all environment-variable- or bind-mounted-file-
driven; see [Quick Start](#quick-start) and
[Module Environment Variables](#module-environment-variables).

## Services

| Service               | Description                                    | Egress                  | Network |
|------------------------|------------------------------------------------|--------------------------|---------|
| `triage-collector`     | Queries Loki, normalizes, aggregates, persists | None                     | troxy   |
| `triage-analyst`       | Reads aggregates, calls Claude, emails report  | `api.anthropic.com` only | shares `triage-egress-guard`'s netns |
| `triage-egress-guard`  | Root sidecar; the only source of egress rules  | n/a (firewall itself)    | troxy   |
| `triage-cli`           | Operator CLI (`verdict set`), bundled into the analyst image | none      | n/a     |

Not a long-running stack — `docker compose run --rm`, driven by a systemd
timer (see [Scheduling](#scheduling)). No Traefik, no Authentik, no HTTP
surface at all.

## Why this exists

The shell script this replaces concatenated raw Loki JSON into a prompt
(truncated at 102400 bytes/query), shelled out to `claude -p` for
interactive-auth-dependent inference, and asked for JSON back in prose with
no enforced shape, no persistence, no cost accounting, and no aggregation —
so token spend scaled with *log volume*, not distinct problems. Full
rationale and the point-by-point design response: [`docs/spec.md`](docs/spec.md).

## Architecture

### Collector/analyst egress split

Only `triage-analyst` can reach the internet, and only `api.anthropic.com`.
`triage-collector` queries Loki and writes aggregates to Postgres; it never
talks to `triage-analyst` over the network — handoff is a shared Postgres
table. `triage-analyst` never sees a raw log line, only normalized templates
that are structurally incapable of carrying a secret, IP, or user identifier
(see [Normalization](#normalization-the-redaction-claim)).

`triage-egress-guard` enforces this: a root sidecar with `NET_ADMIN`/`NET_RAW`
(the *only* container in this module with either) that resolves
`api.anthropic.com`, `POSTGRES_HOST`, and the mail relay host, then applies a
fail-closed `iptables OUTPUT` allowlist scoped to those resolved IPs —
`triage-analyst` shares its network namespace (`network_mode:
service:triage-egress-guard`) and inherits the rules. Anthropic's IPs aren't
static, so the allowlist is rebuilt every `TRIAGE_EGRESS_REFRESH_SECONDS`
(default 300s). A resolution failure — at startup or on refresh — keeps the
previous rule set rather than opening up; policy is set to `DROP` before the
chain is ever flushed, so there's no window where `OUTPUT` defaults to
accept. `triage-analyst`'s `depends_on: condition: service_healthy` gates its
startup on the guard having applied rules at least once. Full mechanism and
the empirical verification (Anthropic reachable, Postgres reachable at the
network layer, an arbitrary third host silently dropped) in
[ADR-015](docs/architecture_decisions.md#adr-015-collectoranalyst-egress-split).

### Normalization (the redaction claim)

Each log line is reduced to a template by replacing variable substrings —
timestamps, UUIDs, IPv4/IPv6, MAC addresses, emails, URLs, absolute paths,
long hex runs, labelled PIDs, remaining numbers — with typed placeholders, in
priority order so a generic decimal pattern can't swallow an IP octet. Two
effects: token spend drops by roughly (lines ÷ distinct templates), and
redaction becomes a structural property enforced by a property-based test
suite, not by inspection or prompt instruction. `template_hash` is a SHA-256
over `(service_name, logger, normalized_template)` — not template text alone
— so two structurally identical lines from different services can't collapse
and let an operator's `benign` verdict on one silently suppress an unrelated
issue elsewhere. Details:
[ADR-016](docs/architecture_decisions.md#adr-016-normalization-as-a-redaction-mechanism-not-a-filter).

### Structured output

Claude's response shape is forced via Messages API tool-use
(`tool_choice: {"type": "tool", ...}`, `strict: true`) rather than
prompt-instructed JSON — no fence-stripping, no empty-output handling, no
schema drift.
[ADR-017](docs/architecture_decisions.md#adr-017-structured-output-via-forced-tool-use-not-prompt-instructed-json).

### Suppression loop

Templates with a `benign` verdict are filtered out **before** the API
call — cost saving and noise reduction in one move. `watch` templates are
always sent with the operator's note attached. Record a verdict without
touching a file:

```bash
docker compose exec triage-analyst triage-cli verdict set <template_hash> benign --note "known noisy WS reconnect"
```

`finding.status` (`new`/`recurring`/`escalating`/`resolved`) is computed by
the collector from history, never asked of the model — the model classifies
severity, the database decides novelty.

## Cost control

- Default model `claude-haiku-4-5` — classification over pre-aggregated,
  pre-redacted input doesn't need a larger tier; escalate only if eval data
  shows under-classification on real logs.
- Prompt caching on the static system prompt (evidence rules + known
  patterns).
- Hard monthly budget, default $20 via `TRIAGE_MONTHLY_BUDGET_USD`. When
  exhausted, the run still completes and still emails — aggregation and
  history, no model triage — and says so plainly rather than failing
  silently.
- Every run's `input_tokens`/`output_tokens`/cache tokens/estimated cost is
  recorded in `api_call` and shown as a footer line on the report.

## Prerequisites

- Spoke hub deployed with `troxy` network and `postgres-hub` running (shared
  database — see [Database](#database))
- Anthropic API key
- A mail relay exposing `POST /send {to, subject, body_text, body_html}`
  (optional — reports still persist to Postgres if unset; see
  [Notes](#notes))

## Database

Uses the hub's shared PostgreSQL (`postgres-hub`) rather than a module-local
container. The `hub_postgres` section in `stack.yml` declares the database
and role that `make provision-db MODULE=triage` creates.

- Database: `triage`
- Role: `triage_app` — a distinct, non-superuser role (not the bootstrap
  `postgres` role), granted only `SELECT`/`INSERT`/`UPDATE` on this module's
  six tables. See `docs/spec.md` §6 for why this matters — it's the exact
  mistake that made GeneGnome's row-level security inert.

Schema (versioned, forward-only migrations under `migrations/`): `run`,
`log_template`, `template_occurrence`, `verdict`, `finding`, `api_call`.

## Quick Start

```bash
# 1. Secrets
mkdir -p ${SECRETS_DIR}/triage
openssl rand -base64 32 > ${SECRETS_DIR}/triage/triage_app_psql_password
echo "sk-ant-..."          > ${SECRETS_DIR}/triage/anthropic_api_key
chmod 600 ${SECRETS_DIR}/triage/*

# 2. Config
cp .env.example .env
# edit .env — at minimum TRIAGE_LOKI_BASE_URL and TRIAGE_MAIL_TO
cp known_patterns.md.example known_patterns.md   # optional; see below

# 3. Provision the hub database + role
make provision-db MODULE=triage

# 4. Build
docker compose build

# 5. Run once (also what the systemd timer does)
scripts/maintenance/run_triage.sh
```

### Dry run

Both binaries accept `--dry-run`: query/normalize/aggregate (collector) or
build-the-prompt/render-the-report (analyst) run for real, but every
Postgres write, the Anthropic call, and the mail send are replaced with a
printed preview — safe to run against production Loki/Postgres with no
side effects.

```bash
docker compose run --rm triage-collector triage-collector --dry-run
docker compose run --rm triage-analyst triage-analyst --dry-run
```

`triage-analyst --dry-run` operates on the oldest `running` row in `run`
(the same one a real run would pick up) and leaves it untouched — a real
analyst run afterward still processes it normally. Prints the exact system
prompt size, the full user message that would be sent to the model, and the
email body that would be mailed.

Seed institutional knowledge into the model's cached system prompt by
editing `known_patterns.md` (gitignored, site-specific — one `## heading`
per pattern, prose underneath). This is **not** the same as a `verdict` row:
`known_patterns.md` is prose the model reads every run, while
`triage-cli verdict set` records a specific observed template as
`benign`/`known-issue`/`watch` in Postgres and is excluded from the API call
entirely.

## Module Environment Variables

| Variable                        | Default                          | Description                                  |
|----------------------------------|-----------------------------------|-----------------------------------------------|
| `TRIAGE_COLLECTOR_IMAGE`/`_TAG`  | `${INSTANCE_NAME}/triage-collector:0.1.0` | Collector image               |
| `TRIAGE_ANALYST_IMAGE`/`_TAG`    | `${INSTANCE_NAME}/triage-analyst:0.1.0`   | Analyst image                 |
| `TRIAGE_EGRESS_GUARD_IMAGE`/`_TAG` | `${INSTANCE_NAME}/triage-egress-guard:0.1.0` | Egress sidecar image     |
| `TRIAGE_POSTGRES_DB`             | `triage`                          | Database name                                |
| `TRIAGE_LOKI_BASE_URL`           | `http://loki:3100`                | Loki base URL                                |
| `TRIAGE_LOKI_TENANT_ID`          | `fake`                            | Loki tenant header                           |
| `TRIAGE_LOOKBACK_HOURS`          | `24`                              | Query window                                 |
| `TRIAGE_EXEMPLAR_LIMIT`          | `3`                               | Verbatim exemplar lines kept per template    |
| `TRIAGE_MODEL`                   | `claude-haiku-4-5`                | Anthropic model                              |
| `TRIAGE_MONTHLY_BUDGET_USD`      | `20`                              | Hard monthly spend cap                       |
| `TRIAGE_MAX_TOKENS`              | `4096`                            | Max output tokens per call                   |
| `TRIAGE_KNOWN_PATTERNS_PATH`     | `/app/known_patterns.md`          | In-container path to the patterns file       |
| `TRIAGE_EGRESS_ANTHROPIC_HOST`   | `api.anthropic.com`               | Host the egress guard allowlists             |
| `TRIAGE_EGRESS_REFRESH_SECONDS`  | `300`                             | Allowlist rebuild interval                   |
| `TRIAGE_MAIL_RELAY_HOST`         | `mail-relay`                      | Mail relay hostname (bare host, not a URL — see [Notes](#notes)) |
| `TRIAGE_MAIL_RELAY_PORT`         | `8000`                            | Mail relay port                              |
| `TRIAGE_MAIL_TO`                 | _(empty)_                         | Report recipient; unset skips email entirely |
| `INSTANCE_NAME`                  | _(from hub)_                      | Used in image names and the report subject   |

## Secrets

Mapped via `modules.yml` `secrets_map`:

| Secret name                  | File path under `${SECRETS_DIR}`   | Purpose                                   |
|-------------------------------|-------------------------------------|--------------------------------------------|
| `triage_app_psql_password`    | `triage/triage_app_psql_password`   | Postgres password for `triage_app`         |
| `anthropic_api_key`           | `triage/anthropic_api_key`          | Anthropic API key — `triage-analyst` only, never mounted into `triage-collector` |

## Scheduling

Not a long-running service — `scripts/maintenance/run_triage.sh` runs the
collector then the analyst via `docker compose run --rm`, tearing the
egress-guard's netns down on exit. Install via systemd user units
(`scripts/maintenance/spoke_triage.service`/`.timer`, hardening baseline
copied verbatim from `spoke`'s `crowdsec_weekly_summary.service`):

```bash
# edit ExecStart in spoke_triage.service to the absolute path first
cp scripts/maintenance/spoke_triage.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now spoke_triage.timer
```

Runs daily at 06:00 with 5 minutes of jitter (`RandomizedDelaySec=300`) —
after `TRIAGE_LOOKBACK_HOURS`' worth of logs (default a full day) has
accumulated.

## Custom builds

Both `triage-collector` and `triage-analyst` are multi-stage Rust builds
(`rust:1-slim` builder targeting `x86_64-unknown-linux-musl`, `alpine:latest`
runtime, static binary, non-root). `triage-egress-guard` is plain Alpine +
`iptables`/`bind-tools` running a POSIX shell entrypoint — no compiled app.
Build with `docker compose build`.

## Notes

- **Mail relay wire contract**: `POST /send` with
  `{to, subject, body_text, body_html}`; the relay owns the `From` address
  (its own `MAIL_FROM_EMAIL`), so `spoke-triage` never sets one. Host/port
  are separate env vars rather than a single URL because
  `triage-egress-guard` needs a bare hostname to `dig` without parsing a URL
  apart in POSIX shell — a deliberate departure from `spoke-backup`'s
  single-`MAIL_RELAY_URL` convention.
- **Mail relay resolution is best-effort** in the egress guard: if the relay
  host fails to resolve, the Postgres + Anthropic rules still apply and the
  run still classifies and persists — only that cycle's email fails. Losing
  a report shouldn't block the core mission.
- **`TRIAGE_MAIL_TO` unset** skips email entirely (logged, not an error) —
  findings still land in Postgres and are queryable directly.
- **`triage-cli` has no `DATABASE_URL`** of its own; it builds the connection
  from the same `POSTGRES_HOST`/`POSTGRES_PORT`/`TRIAGE_POSTGRES_DB` +
  `TRIAGE_APP_PSQL_PASSWORD_FILE` vars `triage-analyst`'s own config uses,
  since it's invoked via `docker compose exec triage-analyst`, not run
  standalone.
## Grafana Dashboard

`grafana/dashboards/spoke_triage_overview.json` (findings by severity,
token spend/cost trend, top recurring templates, new templates in window,
run health history) lives in this repo rather than `spoke-monitoring` — the
content belongs with the module it visualizes; `spoke-monitoring` just hosts
Grafana and provisioning mounts.
[ADR-018](docs/architecture_decisions.md#adr-018-grafana-dashboard-provisioning-lives-in-spoke-triage)
covers the rationale. Every panel queries a hardcoded datasource uid
(`spoke-triage-postgres`, no `$DS_` variable prompt) — a Postgres datasource
with that exact uid must exist before the dashboard renders.

1. In `spoke-monitoring`, bind-mount this repo's provisioning files into
   Grafana (two lines added to the `grafana` service's `volumes:` — see
   that repo's own docs for the exact path spoke-triage is checked out to):
   ```yaml
   - ${SPOKE_DIR}/modules/triage/grafana/provisioning/dashboards.yaml:/etc/grafana/provisioning/dashboards/triage.yaml:ro
   - ${SPOKE_DIR}/modules/triage/grafana/dashboards:/etc/grafana/dashboards/triage:ro
   ```
2. Copy `grafana/provisioning/datasource.yaml.example` to
   `grafana/provisioning/datasource.yaml` (gitignored — holds a password),
   fill in `triage_app`'s password, and bind-mount it the same way as
   `dashboards.yaml` above, into
   `/etc/grafana/provisioning/datasources/triage.yaml`.
3. Recreate `grafana` (`make recreate MODULE=monitoring SERVICE=grafana` or
   equivalent) — the "Spoke Triage" folder and its dashboard appear on next
   provisioning scan (`updateIntervalSeconds: 60`).

## References

- [`docs/spec.md`](docs/spec.md) — full design spec
- [`docs/architecture_decisions.md`](docs/architecture_decisions.md) — ADR-015 through ADR-018
- [Anthropic Messages API](https://docs.claude.com/en/api/messages)
- [SQLx](https://docs.rs/sqlx/latest/sqlx/)

## License

MIT
