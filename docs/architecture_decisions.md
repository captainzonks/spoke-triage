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
# Version: 0.3.0
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

## ADR-016: Structural Redaction as the Primary Mechanism, With a Best-Effort Credential Filter Layered On

**Decision**: Log-line normalization (spec §4, patterns 1–11) remains the
primary redaction mechanism for data crossing the collector→analyst
boundary, and is a whitelist by construction. A second, narrower pass
(spec §4, patterns 12–14: labeled credential fields, known credential ID
prefixes, long base64-alphabet runs) is layered on top specifically to
catch credential/token shapes, which are not a variable *shape* the
whitelist alphabet models — they're free-form alphabetic entropy that
survives normalization's digit/structure-only passes untouched.

**Context**: This ADR originally claimed normalization was the *sole*
redaction mechanism, with no secondary filter, on the reasoning below
(kept, because it's still correct for what it covers). An external review
of this repo demonstrated that claim was stronger than the implementation:
`password=hunter2SuperSecret`, an AWS access key, an Anthropic API key, and
a GitHub PAT all survived `normalize()` with only their digits replaced —
the alphabetic characters carrying the actual secret passed straight
through. Two fixes were considered:

- **(a) — chosen**: add curated credential-shape patterns (labeled fields
  like `password=`/`token=`, known prefixes like `AKIA`/`ghp_`/`sk-ant-`,
  and long base64-alphabet runs for unlabeled/unprefixed secrets like a
  Basic-auth value). This is honestly a blocklist for this one layer —
  the trade this ADR's original argument said not to make — but it's
  cheap, testable, and closes the demonstrated leaks.
- **(b) — measured, rejected**: replace any sufficiently long run mixing
  character classes (letters+digits) with `<TOKEN>`, regardless of shape,
  closer to a real structural guarantee. Measured against this repo's
  golden corpus (`common/tests/golden_normalize.rs`, six real services)
  plus a broader probe of realistic non-secret identifiers: it left the
  8-line golden corpus untouched, but consumed `traefik_v3.1.2`,
  `container=authentik-worker-1`, and `worker-pool-3a` whole, destroying
  the service-identifying text an analyst needs to triage the finding.
  Rejected on that measured evidence, not a guess.

**Rationale** (original, still applies to patterns 1–11):
- Normalization is a whitelist by construction for the shapes it models:
  the output alphabet is `<TIMESTAMP>`, `<UUID>`, `<IPV4>`, `<IPV6>`,
  `<MAC>`, `<EMAIL>`, `<URL>`, `<PATH>`, `<HEX>`, `<PID>`, `<NUM>`, and
  literal template text. Nothing outside that alphabet can appear in a
  template for those shapes.
- The redaction property for patterns 1–11 is testable and enforceable
  (spec §8) rather than a matter of ongoing regex maintenance.
- It composes with the cost-optimization requirement (spec §1.1) instead
  of competing with it — the same normalization pass that redacts is the
  pass that enables aggregation.
- Verbatim exemplar lines are still retained, but **locally in Postgres
  only**, never sent to the API — satisfying the evidence-rule requirement
  (spec §7) that findings be traceable to real log content, without ever
  putting that raw content in an outbound request.

**Consequences**:
- Normalization pattern coverage (§4's ordered list, patterns 1–11)
  remains a security-relevant surface — a new variable-substring pattern
  that should be redacted but isn't yet caught requires updating the
  normalizer, not just adding a filter rule.
- The credential layer (patterns 12–14) is explicitly a best-effort
  blocklist, not a structural guarantee: a credential shape not yet
  enumerated (a new provider's key format, an unlabeled non-base64 secret)
  can still survive. ADR-013's threat model names "credentials leaked into
  error messages, session tokens" as the first thing the egress split
  exists to contain — this layer narrows that exposure but does not close
  it to zero the way patterns 1–11 close IP/email/UUID/path leakage.
  `common/src/normalize.rs`'s property tests assert the specific shapes
  this layer is known to catch; they are not, and cannot be, a proof of
  completeness.
- Templates that differ only in a value neither pass recognizes as
  variable (e.g. a service-specific ID format) will under-aggregate rather
  than over-redact — the failure mode leans toward more distinct templates
  (higher cost, same safety) rather than a leaked value (lower cost,
  broken safety). This is the correct direction to fail in, and is why
  option (b) above was rejected: it would have inverted this trade for the
  credential layer, over-redacting into safety at the cost of triage
  usefulness, for a benefit the golden-corpus measurement didn't show was
  needed.

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

---

## ADR-019: Test-Only CI, No Deploy CI

**Decision**: Add a GitHub Actions workflow (`.github/workflows/ci.yml`)
that runs `cargo test --workspace` and `cargo clippy --workspace
--all-targets -- -D warnings` on every push to `main` and every PR.
`cargo fmt --check` is deliberately not included yet — this repo has
pre-existing formatting drift across most files, unrelated to this
change, and turning that check on now would make CI red from the first
run for a reason unrelated to what anyone actually broke. Add it once a
separate whole-repo `cargo fmt` pass lands.

**Context**: Spoke's own position is "no CI" — a build-and-deploy runner
on a single node would need the Docker socket access the socket-proxy
architecture exists to deny, and a runner cannot restart the stack it
lives inside. That reasoning is sound, but it's an argument about
*deployment*, not about running a test suite. An external review of this
repo demonstrated the gap concretely: `analyst/src/main.rs`'s test helper
fell out of sync with `config::Config` (a field was added to the struct
but not to the test fixture), `cargo build` stayed green because it
doesn't compile tests, and `cargo test --workspace` had been silently
broken since the field was added — with no signal until someone ran it
by hand (see the fix for this in this repo's history, same review round
as this ADR).

**Rationale**:
- A test-only job needs no Docker socket, no host access, and deploys
  nothing — it is not the circular case ("the runner needs the thing it
  would be validating") the original no-CI decision rejected.
- This is exactly the failure mode a test-only gate catches: production
  code changes, a test fixture doesn't, and nothing notices until a human
  happens to run the full suite. GitHub Actions runners are ephemeral and
  have no access to this deployment's secrets, network, or Docker socket
  by construction — there's no new attack surface to reason about.
- Sharpens the existing position rather than reversing it: "no CI" becomes
  "CI that deploys, no; CI that tests, yes" — a more precise decision, not
  a different one.

**Consequences**:
- `cargo clippy -- -D warnings` makes a clippy warning a CI failure, not
  just a local nit — new code must stay clippy-clean, matching what this
  review round already brought the repo to.
- `cargo fmt --check` is explicitly deferred, not silently dropped: the
  repo is not currently `cargo fmt`-clean, and reformatting the whole
  repo is out of scope for this change. Track it as follow-up work rather
  than assuming this ADR covers it.
- A red CI run now means a real regression, not a deploy-environment
  quirk — the job runs on GitHub's generic runners with no dependency on
  this specific server or its state.
