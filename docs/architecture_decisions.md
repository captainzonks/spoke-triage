# ==============================================================================
# architecture_decisions.md - spoke-triage ADR log
# ==============================================================================
# Description: Architecture decision records for spoke-triage. Numbering
#              continues from spoke's docs/architecture_decisions.md
#              (highest existing: ADR-012), since spoke-triage is
#              standalone-first (ADR-008 pattern) and keeps its own ADR log,
#              cross-referenced from spoke rather than merged into it.
# Author: Matt Barham
# Created: 2026-09-08
# Modified: 2026-09-10
# Version: 0.1.2
# ==============================================================================
# Document Type: ADR log
# Audience: Implementers and reviewers of spoke-triage
# Status: Draft — awaiting approval
# ==============================================================================

## ADR-015: Collector/Analyst Egress Split

**Decision**: Split spoke-triage into two containers along a hard egress
boundary — `triage-collector` (no internet access, queries Loki, normalizes,
writes to Postgres) and `triage-analyst` (the only container with egress,
calls the Anthropic API, never touches raw log lines).

**Context**: Every other application container in Spoke is either internal
or fronted by Traefik; none deliberately reaches the public internet.
spoke-triage is the first to need outbound API access as its core function.
The threat model: raw application logs can contain anything an application
happens to log — credentials leaked into error messages, session tokens,
internal IPs, user PII. Sending that unfiltered to a third-party API is an
unacceptable exfiltration surface, independent of how careful the prompt is.

**Rationale**:
- Optimization priority (spec §1.1) already forces aggregation before any
  API call — the collector has to normalize and aggregate regardless of
  security concerns, purely for cost. The egress split piggybacks on work
  that already has to happen for cost reasons, at near-zero marginal cost.
- A container with no egress cannot exfiltrate, full stop — no prompt
  discipline, no output filter, no code review can provide the same
  guarantee as a network boundary that doesn't exist.
- Normalization (spec §4) makes the boundary meaningful rather than
  theatrical: what crosses from collector to analyst is structurally
  incapable of carrying a secret, IP, or identifier, enforced by the
  redaction test suite (spec §8).
- Handoff is via a shared Postgres table, not a network call between the
  two containers — no need for the collector to have any outbound
  capability whatsoever, including to the analyst.

**Consequences**:
- Two containers to build, deploy, and secure instead of one — more
  operational surface, justified by the security property gained.
- The analyst container needs its own hardening (cap_drop, read-only root,
  non-root, resource limits — spec §3.2) since it's Spoke's first
  internet-facing application container.
- Egress restriction to `api.anthropic.com` specifically (not "any
  internet") requires a DNS-refresh mechanism, since Anthropic's IPs are
  not static — adds a small operational component (resolver sidecar or
  cron-refreshed allowlist) that must fail closed on stale resolution.
- If a future feature needs the collector to reach the internet (e.g.
  fetching an external threat-intel feed), that is a new architectural
  decision requiring its own ADR — this boundary is not meant to erode
  incrementally.

**Implementation** (spec §3.2): checked `spoke-redm` and `spoke-piped` first
— neither fits. redm's Tailscale sidecar solves *ingress* isolation (game
port reachable only over Tailnet), not egress filtering, and piped-resolver
deliberately has unrestricted egress (arbitrary YouTube CDN IPs). Fell back
to the destination-IP-allowlist sidecar the spec anticipated:
`triage-egress-guard` (`dockerfiles/triage-egress-guard/`) owns the network
namespace shared with `triage-analyst` via `network_mode:
service:triage-egress-guard`, and is the only container in this module that
runs as root / holds `NET_ADMIN`+`NET_RAW`.

- **Mechanism**: on start, sets `iptables -P OUTPUT DROP`, bootstraps
  loopback + DNS (port 53) `ACCEPT` rules (needed to resolve anything at
  all — an earlier draft set the DROP policy before any DNS path existed
  and deadlocked the container against its own resolver), then resolves
  both `api.anthropic.com` and `POSTGRES_HOST` via `dig`, and adds
  `ACCEPT` rules scoped to those resolved IPs on 443/`POSTGRES_PORT`
  respectively. Both must resolve for a rule update to apply.
- **Refresh cadence**: re-resolves and rebuilds the allowlist every
  `TRIAGE_EGRESS_REFRESH_SECONDS` (default 300s) via a plain shell loop —
  no cron daemon, since a `while`+`sleep` loop is one fewer dependency for
  the same result (spec §1.1 optimization priority extended to deps).
- **Failure mode — fails closed, not open**: policy `DROP` is set before
  the first resolution attempt, so a crash before the first successful
  resolution never falls back to the container's default-`ACCEPT` policy.
  On refresh, a failed resolution logs a warning and leaves the previous
  (still-valid) rule set in place rather than flushing to an open or empty
  chain. Verified empirically: with the guard's rules applied, a container
  sharing its netns reached `api.anthropic.com` (TLS handshake succeeded)
  and `POSTGRES_HOST` (TCP SYN/ACK reached the host — refused only because
  no service was listening in the test rig), while a request to an
  arbitrary third host (`example.com`) timed out (silently dropped, not
  refused) — confirming default-deny, not a leaky allowlist.
- **Readiness gate**: `triage-analyst` has `depends_on: triage-egress-guard:
  condition: service_healthy`; the guard's `HEALTHCHECK` only passes once
  the first rule application has succeeded (a marker file written at the
  end of `apply_rules()`), so the analyst never starts against a
  default-open or not-yet-configured netns.

---

## ADR-016: Normalization as a Redaction Mechanism, Not a Filter

**Decision**: Log-line normalization (spec §4) is the sole redaction
mechanism for data crossing the collector→analyst boundary. There is no
separate secondary redaction/filter pass on top of it.

**Context**: The obvious alternative — send raw or lightly-redacted log
lines and run a regex/filter pass to strip anything that looks like a
secret — was considered and rejected. A filter is a blocklist: it catches
patterns you thought to write a rule for, and silently passes anything you
didn't. Given the open-ended nature of what applications can log, a
blocklist approach cannot provide a real security guarantee, only a
best-effort one.

**Rationale**:
- Normalization is a whitelist by construction: the output alphabet is
  `<TIMESTAMP>`, `<UUID>`, `<IPV4>`, `<IPV6>`, `<MAC>`, `<EMAIL>`, `<URL>`,
  `<PATH>`, `<HEX>`, `<PID>`, `<NUM>`, and literal template text. Nothing
  outside that alphabet can appear in a template, so there's no category of
  secret shape that slips through by omission the way a blocklist rule
  would.
- The redaction property becomes testable and enforceable (spec §8) rather
  than a matter of ongoing regex maintenance and inspection.
- It composes with the cost-optimization requirement (spec §1.1) instead of
  competing with it — the same normalization pass that redacts is the pass
  that enables aggregation.
- Verbatim exemplar lines are still retained, but **locally in Postgres
  only**, never sent to the API — satisfying the evidence-rule requirement
  (spec §7) that findings be traceable to real log content, without ever
  putting that raw content in an outbound request.

**Consequences**:
- Normalization pattern coverage (§4's ordered list) becomes a
  security-relevant surface — a new variable-substring pattern that should
  be redacted but isn't yet caught (e.g. a new secret-key format Spoke
  starts using) requires updating the normalizer, not just adding a filter
  rule. This is a real maintenance cost, offset by being caught in code
  review and tested against, rather than silently degrading.
- Templates that differ only in a value the normalizer doesn't yet
  recognize as variable (e.g. a service-specific ID format) will
  under-aggregate rather than over-redact — the failure mode leans toward
  more distinct templates (higher cost, same safety) rather than a leaked
  value (lower cost, broken safety). This is the correct direction to fail
  in.

---

## ADR-017: Structured Output via Forced Tool Use, Not Prompt-Instructed JSON

**Decision**: The triage report schema is enforced via a Messages API tool
definition with `strict: true` and `tool_choice` forcing that tool — not by
asking the model for JSON in the system prompt.

**Context**: `spoke_log_analysis.sh` asks for "a single valid JSON object"
in prose and then has to strip markdown fences and handle empty/malformed
output as a runtime concern. This is exactly the "unenforced output shape"
defect from spec §1.

**Rationale**:
- `strict: true` on the tool's `input_schema` (`additionalProperties: false`
  + `required`) guarantees `tool_use.input` validates exactly, server-side —
  eliminates an entire class of parsing failures the current script has to
  handle defensively.
- Forcing the tool via `tool_choice: {"type": "tool", "name":
  "triage_report"}` removes the failure mode where the model responds with
  prose instead of the report.
- This aligns with the optimization priority (spec §1.1): no wasted output
  tokens on markdown fences, preamble, or retries caused by malformed JSON.

**Consequences**:
- The report schema becomes an API contract (JSON Schema) rather than a
  prose description — schema changes are a versioned, testable artifact
  instead of a prompt-wording change.
- `status: new | recurring | escalating | resolved` is deliberately **not**
  part of the tool schema the model fills in — it's computed by the
  collector from `log_template` history after the API call returns. This
  keeps the model's job to what it can actually judge (severity, whether an
  issue exists) and keeps a deterministic, auditable computation
  (novelty/recurrence) out of the model's hands entirely.

---

## ADR-018: Grafana Dashboard Provisioning Lives in spoke-triage

**Decision**: The dashboard JSON lives in `spoke-triage/grafana/dashboards/`,
not in `spoke-monitoring`. Enabling it in `spoke-monitoring`'s Grafana
requires only a provisioning-directory mount and one compose volume edit in
`spoke-monitoring` — no dashboard content lives there.

**Context**: `spoke-monitoring` currently runs Grafana with no provisioned
dashboards at all — this is the first one, so it also establishes the
provisioning pattern for dashboards that follow. The build brief's
out-of-scope clause originally allowed only `modules.yml.example`
registration, ADRs, and a deprecation note as touches to `spoke`/
`spoke-monitoring` — provisioning a dashboard requires slightly more than
that (a mount + one volume line), which is called out explicitly here
rather than silently exceeding the stated scope.

**Rationale**:
- Standalone-first (ADR-008 in `spoke`, external-module pattern): a reader
  who has never seen Spoke should be able to run spoke-triage and get a
  working dashboard by pointing Grafana provisioning at this repo's
  `grafana/dashboards/` directory — the content belongs with the thing it
  visualizes, not with the generic monitoring stack.
- Keeps `spoke-monitoring` generic — it becomes the provisioning host for
  any module's dashboards over time, not a dumping ground for one module's
  JSON.
- The touch to `spoke-monitoring` is minimal and mechanical (a
  provisioning-directory bind mount pointed at spoke-triage's checkout path,
  one compose volume line) — it does not require `spoke-monitoring` to know
  anything about spoke-triage's schema or content.

**Consequences**:
- Deploying the dashboard requires a `spoke-monitoring` compose change in
  addition to deploying spoke-triage itself — a two-repo coordination step
  that must be documented in spoke-triage's README and in the
  `spoke-monitoring` deprecation/registration note.
- Establishes the pattern other future modules should follow for their own
  Grafana dashboards — worth getting right here since it's precedent-setting.
