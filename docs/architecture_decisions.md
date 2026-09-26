# ==============================================================================
# architecture_decisions.md - spoke-triage ADR log
# ==============================================================================
# Description: Architecture decision records for spoke-triage. Numbers
#              come from the single ADR sequence shared by spoke and every
#              module (spoke docs/module_development.md), since spoke-triage
#              is standalone-first (ADR-008 pattern) and keeps its own ADR
#              log, cross-referenced from spoke rather than merged into it.
# Author: Matt Barham
# Created: 2026-09-08
# Modified: 2026-09-26
# Version: 0.5.0
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

## ADR-020: The Analyst Claims the Newest Pending Run and Retires the Rest

**Decision**: `triage-analyst` selects the **newest** run still in
`running` status (`ORDER BY id DESC`), not the oldest, and marks every
older `running` run `abandoned` (migration 0004) in the same pass. The
emailed report's "Period" line renders the analyzed run's actual
`window_start`/`window_end` instead of the configured
`TRIAGE_LOOKBACK_HOURS`. `TRIAGE_LOOKBACK_HOURS` is now read only by
`triage-collector`, which is the component that defines the window.

**Context**: `run_triage.sh` runs the collector and then the analyst as
one cycle, so under normal operation exactly one run is in `running`
when the analyst starts, and oldest-first and newest-first agree. They
diverge the moment an analyst pass fails after its collector succeeded —
observed in production on 2026-09-17, when the timer fired 17 minutes
after a host boot, the collector completed, and the analyst did not.
That left run 16 stranded in `running` forever.

Because the analyst took the *oldest* pending run, every subsequent
cycle then collected a fresh window and analyzed the previous one:

```
run 16  collected Sep 17 23:14   analyzed Sep 18 06:06
run 17  collected Sep 18 06:05   analyzed Sep 19 06:02   <- emailed as "Last 24 hours"
run 18  collected Sep 19 06:01   still `running`
```

The failure is silent and permanent. There is always exactly one run in
`running`, so nothing looks stuck; each day's email arrives on time, is
well-formed, and describes a window that ended 24 hours before it was
sent. The report's own header said "Period: Last 24 hours", which was
false for every report after the stranding, and was the reason the drift
went unnoticed for two days. The operational cost is real: the Sep 19
email reported `degraded` with nine findings, all of them the boot
cascade from the Sep 17 reboot (services racing DNS and MinIO at
startup). The window that had actually just elapsed was `healthy` with
zero findings.

**Rationale**:
- The report answers "what is the infrastructure doing now". A stale
  window is not a partial answer to that question, it is a wrong one.
- Newest-first makes a failed analyst cost exactly one report. The next
  cycle is correct with no operator intervention, where oldest-first
  required someone to notice the offset and drain the backlog by hand.
- The skipped runs' aggregates (`log_template`, `template_occurrence`)
  are already written and stay queryable, so trend counts and history
  are unaffected; only the run's lifecycle status changes. Retiring them
  is what keeps `running` from accumulating rows that would each cost a
  future cycle.
- `abandoned` rather than reusing `failed`: `failed` is written by the
  collector's own error path, so overloading it would make "the
  collector could not complete" and "the collector completed, nothing
  analyzed it" indistinguishable in history — exactly the distinction
  needed to tell whether Loki or the Anthropic path is the flaky one.
- Rendering the real window is the cheap half of the fix and independent
  of the rest: any future divergence between the intended and analyzed
  window is visible in the email itself rather than requiring a database
  query to detect.

**Consequences**:
- Migration 0004 rewrites `run_status_check`. It is additive (no existing
  value is removed) and applies automatically via `sqlx::migrate!` on the
  collector's next start.
- A run skipped by the analyst is never analyzed. This is deliberate: its
  window has passed and a newer run covers the current state. Its
  aggregates remain in the database, so nothing is lost but the severity
  classification for a window nobody can act on any more.
- Reports no longer state a fixed lookback. Readers see two timestamps,
  which is strictly more information and self-describing when a run
  covers a non-standard window (a manual run, or a changed
  `TRIAGE_LOOKBACK_HOURS`).
- `collector/tests/migrations.rs` gains a case asserting the constraint
  accepts `abandoned` and still rejects unknown statuses.


## ADR-022: Secret, Dependency and Image Scanning in Test-Only CI

**Decision**: Add three scanning workflows and Dependabot version updates
alongside `ci.yml`, and harden `ci.yml` to the hub's `gitleaks.yml`
pattern:

| Workflow | Tool and version | Gate |
|---|---|---|
| `gitleaks.yml` | gitleaks v8.30.1 | Any finding in full git history fails (`--redact --exit-code 1`) |
| `cargo_deny.yml` | cargo-deny 0.20.2 | Advisories, bans, licenses and sources all must pass |
| `trivy.yml` | Trivy 0.74.0 | Fails on HIGH/CRITICAL findings that have a fix; everything else is reported |
| `.github/dependabot.yml` | Dependabot | Weekly PRs for `cargo`, `github-actions`, `docker`; minor and patch grouped |

`cargo_deny.yml` and `trivy.yml` also run weekly on a schedule, because
new advisories and CVEs land without any change to this repo.

**Context**: ADR-019 allowed test-only CI because it deploys nothing and
needs no host access. That boundary covers scanning equally well, and the
repo had none: no secret scan, no dependency audit, and no image scan,
while shipping three container images and a crate graph that includes a
TLS stack. `ci.yml` also referenced actions by mutable tag (`@v4`,
`@stable`) and had no `permissions` block. The first cargo-deny run found
RUSTSEC-2026-0285 in `rustls` 0.23.44 (TLS 1.3 handshake messages accepted
across encryption-level boundaries), fixed by a lockfile bump to 0.23.45
in the same change set.

**Rationale**:
- **Severity gates.** Secrets and RustSec vulnerabilities have no
  acceptable level, so both gate on any finding. cargo-deny also denies
  yanked crates, unmaintained or unsound notices, wildcard version
  requirements and any source other than crates.io; duplicate versions
  only warn, since they come from transitive requirements this repo
  doesn't control. Trivy gates on fixable HIGH/CRITICAL only
  (`--ignore-unfixed`): a finding with no fixed package can't be acted on,
  and failing on it would leave CI red with no remedy. The full
  all-severity table is still printed on every run.
- **License allowlist.** `deny.toml` allows exactly the 11 licenses
  `cargo deny list` reported for this `Cargo.lock` on 2026-09-26:
  Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-2-Clause, BSD-3-Clause,
  BSL-1.0, CDLA-Permissive-2.0, ISC, MIT, Unicode-3.0, Unlicense, Zlib.
  None is copyleft. A new license in the graph fails the check and needs
  a deliberate decision.
- **Workspace path dependencies.** cargo-deny counts
  `spoke-triage-common = { path = "../common" }` as a wildcard unless the
  crate is unpublishable. The four member crates now set
  `publish = false`, which is accurate (they ship as container images,
  never to crates.io) and lets `allow-wildcard-paths` apply.
- **Fixture allowlist: `.gitleaksignore` fingerprints, not inline
  `gitleaks:allow`.** A full-history scan reports each secret at the
  commit that introduced it (`1dce22e`), where the line has no allow
  comment. An inline comment added now would silence only future commits
  and leave the historical findings failing. The two fingerprints
  (`commit:file:rule:line`, rules `github-pat` and `generic-api-key` in
  `common/src/normalize.rs`) are as narrow as gitleaks allows: no file,
  path or rule is allowlisted, so a new secret in the same file still
  fails. The AWS documented example key in the same tests is not
  reported by gitleaks at all.
- **Pinning.** Every action is pinned to a full commit SHA with its
  version in a trailing comment, resolved on 2026-09-26 with
  `git ls-remote` against the upstream release tag. `dtolnay/rust-toolchain`
  publishes no release tags, so it is pinned to the head of its `stable`
  branch; the Rust toolchain it installs still tracks current stable,
  which keeps `cargo test` and `cargo clippy` behaving as under ADR-019.
  Scanner images are pinned by tag and digest. cargo-deny is installed
  from its release tarball and checked against a SHA-256 written into the
  workflow, not against the `.sha256` file published beside it, so a
  replaced release asset fails the job. The official
  `cargo-deny-action` was not used, to keep to one pattern (no
  third-party actions beyond checkout, cache and the toolchain).
- **No marketplace scanner actions.** In March 2026 an attacker
  force-pushed 76 of 77 `aquasecurity/trivy-action` tags and all
  `setup-trivy` tags to credential-stealing code, and published malicious
  Trivy v0.69.4 (plus v0.69.5 and v0.69.6 Docker Hub images)
  ([GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)).
  Any workflow that referenced those tags ran the attacker's code. Running
  the official image by digest removes the mutable-tag path. Trivy 0.74.0
  was released 2026-08-14, after the incident, and is outside the affected
  versions.
- **Why this still fits ADR-019.** Every job runs on GitHub-hosted
  runners with `permissions: contents: read`, `persist-credentials:
  false`, no repository secrets and no `pull_request_target`. The Trivy
  job builds images with the runner's own Docker daemon, never this
  deployment's, and hands them to the scanner as `docker save` tarballs,
  so the scanner container gets no Docker socket at all. Nothing is
  pushed or deployed.

**Versions verified** (2026-09-26):

| Tool | Version | Pin | Checked at |
|---|---|---|---|
| actions/checkout | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` | GitHub releases, `git ls-remote` |
| actions/cache | v6.1.0 | `55cc8345863c7cc4c66a329aec7e433d2d1c52a9` | GitHub releases, `git ls-remote` |
| dtolnay/rust-toolchain | `stable` branch | `6bed0761d98439e5a578e2877258200ad565ba87` | GitHub branches API |
| gitleaks | v8.30.1 | `sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f` | GitHub releases, `ghcr.io` manifest |
| Trivy | 0.74.0 | `sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969` | GitHub releases, `ghcr.io` manifest |
| cargo-deny | 0.20.2 | tarball SHA-256 `9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f` | GitHub releases |

**Consequences**:
- Dependabot security alerts are a repository setting, enabled separately
  from this change; `.github/dependabot.yml` only configures version
  updates.
- Scheduled runs can turn red without a code change. That is the purpose
  of the schedule, not a flake.
- The Dockerfiles use floating bases (`rust:1-slim`, `alpine:latest`), so
  Trivy results move with upstream and Dependabot can't propose a bump
  for `latest`. `trivy.yml` builds with `--pull` so it always scans the
  current base; a locally cached base can be older than what CI sees.
  Pinning the bases is left as follow-up work.
- Trivy scans OS packages only here. The Rust binaries are not built with
  `cargo auditable`, so crate vulnerabilities are covered by cargo-deny,
  not by the image scan.
- CodeQL was not added. Rust has been generally available in CodeQL since
  2025-10-14 (CodeQL CLI 2.23.3), so it can be added later as its own
  decision.
