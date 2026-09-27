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
# Modified: 2026-09-27
# Version: 0.8.0
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

## ADR-025: CodeQL SAST and SBOMs in Test-Only CI

**Decision**: Add static analysis and software bills of materials to the
ADR-022 scanning set, and build the Rust binaries with `cargo auditable` so
both the SBOMs and the existing image gate see the crates that actually
ship:

| Change | Tool and version | Gate |
|---|---|---|
| `codeql.yml` (new) | `github/codeql-action` v4.38.2, languages `rust` and `actions`, `build-mode: none`, default query suite | Report-only: alerts go to code scanning; no branch rule requires it |
| `trivy.yml` 0.2.0 | Trivy 0.74.0 (same digest as ADR-022) | CycloneDX and SPDX SBOM per image, CycloneDX SBOM of the Cargo workspace; validated in the job, uploaded as the `sboms` artifact. The ADR-022 gate step is unchanged |
| Collector and analyst Dockerfiles 0.2.0 | `cargo-auditable` 0.7.6, builder stage only | None of its own; widens what the existing Trivy gate can see |

**Context**: After ADR-022 the repo had secret, dependency and image
scanning, but nothing read the code itself (clippy is a linter, not a
security analyzer), and nothing produced a machine-readable inventory of
what ships. The images were also opaque to Trivy at the crate level: plain
`cargo build` binaries carry no dependency metadata, so the image SBOM of
the deployed `triage-collector` and `triage-analyst` listed
18 components each (17 Alpine packages plus the OS entry) and no crates at all. ADR-022 recorded that gap ("Trivy
scans OS packages only here"); this ADR closes it.

**Rationale**:
- **What CodeQL covers.** Data-flow and structural security queries over
  the Rust workspace (for example `rust/disabled-certificate-check`,
  `rust/cleartext-logging`, `rust/hard-coded-cryptographic-value`), and the
  `actions` queries over `.github/workflows/` (for example, untrusted
  event fields interpolated into `run:` steps). Rust became
  generally available on 2025-10-14 with CodeQL CLI 2.23.3
  ([changelog](https://github.blog/changelog/2025-10-14-codeql-scanning-rust-and-c-c-without-builds-is-now-generally-available/));
  `actions` on 2025-04-22
  ([changelog](https://github.blog/changelog/2025-04-22-github-actions-workflow-security-analysis-with-codeql-is-now-generally-available/)).
  `build-mode: none` is the documented mode for Rust
  ([build options](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-build-options-and-steps-for-compiled-languages)),
  so the job needs no toolchain step and never compiles the workspace.
- **What CodeQL doesn't cover.** CodeQL's default threat model is `remote`:
  environment variables and command-line arguments are `local` sources,
  so injection-style taint queries only fire on data read from the
  network. Two kinds of query ignore the threat model. Structural queries
  (a hard-coded `true` passed to a certificate check, a plain-`http` URL)
  fire on the code's shape; the proof run below used one. Sensitive-data
  queries (cleartext logging and transmission) take as sources values
  CodeQL recognizes as secrets by name, such as the result of
  `read_secret` or a variable called `password`, and they fired on `main`
  from its first analysis (ADR-026). *Corrected 2026-09-27: this bullet
  first said taint queries fire only on network data.*
- **Default suite, not `security-extended`.** The default suite is the
  high-precision set GitHub runs for default setup. `security-extended`
  adds lower-precision queries, and on a small workspace with no remote
  request handlers the likely yield is noise, not findings. Revisit if the
  default suite stays silent for a long time while real bugs turn up
  elsewhere.
- **Report-only.** CodeQL results land in the Security tab and as PR
  annotations. The repository ruleset (a setting, 2026-09-27) requires
  the four ADR-022 checks to pass before merge but deliberately not
  CodeQL: a SAST finding needs a human judgment (fix, or dismiss with a
  reason), and a required check would force that judgment under merge
  pressure.
- **`security-events: write`, the first write-scoped token in this repo.**
  Uploading SARIF to code scanning requires it. Scope: only the `analyze`
  job in `codeql.yml` has it; the workflow's top-level permission stays
  `contents: read`, and every other workflow is unchanged. The permission
  lets the job create and update code scanning analyses; it can't push
  code, change settings or read secrets. For `pull_request` runs from a
  fork, GitHub downgrades every write permission to read, whatever the
  workflow asks for ([workflow syntax,
  `permissions`](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)),
  and code scanning accepts the upload anyway: "code scanning always
  allows the uploading of results when the `pull_request` event triggers
  the action run"
  ([troubleshooting](https://docs.github.com/en/code-security/reference/code-scanning/troubleshoot-analysis-errors/resource-not-accessible)).
  Dependabot PRs run "as if they are from a forked repository", so the
  same rules apply to them. Verified on 2026-09-27 with spoke-triage#8,
  the first Dependabot PR to run `codeql.yml` after it merged: both the
  `rust` and `actions` analyses uploaded to `refs/pull/8/merge` with no
  permission changes.
- **SBOMs.** Every CI run of `trivy.yml` writes seven files: for each
  image a CycloneDX (`<image>.cdx.json`) and an SPDX (`<image>.spdx.json`)
  SBOM, plus `spoke_triage_source.cdx.json` from `trivy fs` on the
  checkout (mounted read-only). The job checks each file parses, has at
  least one component, and carries the exact spec version Trivy 0.74.0
  writes: CycloneDX `specVersion` 1.7 and `spdxVersion` SPDX-2.3, measured
  on a local 0.74.0 run because the v0.74.0 docs still show older example
  values. A Trivy bump that changes either fails validation on purpose.
  Counts go to the job summary. `trivy sbom --exit-code 0` then scans each
  image SBOM for vulnerabilities, informational only, so the ADR-022 gate
  stays the only image gate. The SBOM steps run after the gate with
  `!cancelled()`, so a week where the gate fails still produces SBOMs.
  Artifacts keep the repository default retention (90 days).
- **What the SBOMs don't cover.** The source SBOM omits dev-dependencies
  (Trivy drops them when `Cargo.toml` sits beside `Cargo.lock`): 248 of
  the 264 `Cargo.lock` packages appear, and the 16 missing ones are the
  `proptest`/`tempfile` test tree, which never ships. It also contains one
  nameless component, the virtual workspace root. `triage-egress-guard`
  is Alpine plus a POSIX shell entrypoint with no compiled code, so its
  SBOM is OS packages only, as it should be.
- **`cargo-auditable`.** It embeds the resolved crate list in a
  `.dep-v0` section of each binary at build time, which Trivy reads
  ([Trivy Rust coverage](https://github.com/aquasecurity/trivy/blob/v0.74.0/docs/guide/coverage/language/rust.md)).
  Installed with `cargo install cargo-auditable --locked --version 0.7.6`
  in the builder stage only; the runtime stage and final image gain no
  packages. After the change the image SBOMs list 202 components for `triage-collector` (183 crates) and 352 for `triage-analyst` (332 crates, since it also ships `triage-cli`), from the CI run on spoke-triage#12.
  Cost: `cargo install` adds a compile to each uncached builder build, and
  one more crates.io tool enters the build supply chain (its own
  dependencies are pinned by `--locked`). The embedded list is a few KB of
  compressed JSON and names only crates already public in `Cargo.lock`.
  Because the image gate now sees crates too, a fixable HIGH/CRITICAL
  RustSec advisory can fail `trivy.yml` as well as `cargo_deny.yml`.
- **`cargo-auditable` over-reports optional dependencies.** It takes its
  crate list from `cargo metadata`, which counts an optional dependency as
  present when a feature names it with the weak `dep?/feature` syntax.
  reqwest's `__rustls-ring` feature contains `quinn?/ring`, so `quinn`,
  `quinn-proto` and `quinn-udp` (reqwest's HTTP/3 stack) appear in the
  embedded list, though `http3` is never enabled and `cargo tree --target
  all` shows none of them. The stripped collector binary contains no
  `quinn` strings. The first scan with the new metadata failed the gate
  on `quinn-proto` 0.11.13 (RUSTSEC-2026-0037 and RUSTSEC-2026-0185);
  cargo-deny, which follows cargo's real feature resolution, correctly
  passed. The fix was a lockfile bump to 0.11.18 rather than an ignore
  entry: it clears both gates without a suppression and leaves the
  version already patched if HTTP/3 is ever turned on. Expect the same
  pattern again. When the image gate flags a crate that cargo-deny
  passes, check `cargo tree` before assuming it ships.
- **DAST is out of scope.** Dynamic testing needs a running service to
  probe. spoke-triage exposes no HTTP surface: the collector and analyst
  are batch jobs started by a systemd timer, with no listener, and the
  egress guard only writes firewall rules.
- **Why this still fits ADR-019.** Both workflows run on GitHub-hosted
  runners, with no repository secrets, `persist-credentials: false` and no
  `pull_request_target`. CodeQL never builds or runs the code. The SBOM
  steps reuse the image tarballs the scan already built and mount the
  checkout read-only; no scanner gets a Docker socket. The only write
  permission is the code scanning upload described above. Nothing is
  pushed, published or deployed; the Dockerfile change reaches Rome only
  when it's rebuilt by hand (ADR-021).

**Versions verified** (2026-09-27):

| Tool | Version | Pin | Checked at |
|---|---|---|---|
| github/codeql-action | v4.38.2 | `2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2` | GitHub releases, tag dereferenced via the git refs API (annotated tag) |
| actions/upload-artifact | v7.0.1 | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` | GitHub releases, git refs API |
| actions/checkout | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` | Unchanged from ADR-022, re-checked |
| cargo-auditable | 0.7.6 | `--locked --version 0.7.6` | GitHub releases (rust-secure-code/cargo-auditable), crates.io API |
| Trivy | 0.74.0 | unchanged digest (ADR-022) | Docs read at tag v0.74.0 |

**Consequences**:
- Findings arrive in two places with different weights: the ADR-022 gates
  block a merge, CodeQL alerts wait in the Security tab for a decision.
  Dismissals need a written reason.
- `codeql.yml` also runs weekly, so new queries shipped in a CodeQL
  release can raise alerts on unchanged code.
- A deliberately insecure test commit showed the Rust analysis reports
  alerts: spoke-triage#13 added `danger_accept_invalid_certs(true)` to the
  Loki client, and CodeQL raised `rust/disabled-certificate-check` (high)
  at `collector/src/loki.rs:71`. The draft PR was closed unmerged and its
  branch deleted; the commit stays reachable through `refs/pull/13/head`.
- A PR that introduces an alert gets a failing `CodeQL` check. The
  ruleset doesn't require it, but the standing rule of merging only on
  all-green checks means such a PR waits for the alert to be fixed or
  dismissed with a reason.
- The base images are still floating (`rust:1-slim`, `alpine:latest`), so
  SBOM contents move with upstream between runs. Pinning them is separate
  work.

## ADR-026: Secrets Kept Out of Config Behind a Redacting Type; Loki Over Internal HTTP Accepted

**Decision**: Move every secret out of the `Config` structs into a separate
`Secrets` struct holding a `Secret` newtype, and accept plain HTTP to Loki
on the internal Docker network as a recorded risk:

| Alert | Rule | Location | Outcome |
|---|---|---|---|
| #3–#8 | `rust/cleartext-logging` | `analyst/src/main.rs:74, 91, 116, 124, 125, 143` | Fixed by the secrets split |
| #9 | `rust/cleartext-transmission` | `collector/src/loki.rs:88` | Fixed by the secrets split |
| #2 | `rust/non-https-url` | `collector/src/loki.rs:88` | Dismissed as "won't fix", with this ADR as the reason |

**Context**: The first CodeQL analysis of `main` after ADR-025 landed
(`52ef73c`, 2026-09-27) raised eight alerts. They didn't show up on the
ADR-025 PR itself because CodeQL reports on a pull request only the
alerts inside the lines that PR changed
([changelog, 2025-05-28](https://github.blog/changelog/2025-05-28-incremental-security-analysis-makes-codeql-up-to-20-faster-in-pull-requests/)),
and that PR didn't touch the flagged lines. The ADR-025 report checked
`main` for open alerts before the PR merged, when `main` had never been
analyzed, so its "0 open alerts on `main`" was true but meant nothing.

The SARIF data-flow paths show one cause for seven of the eight. In both
binaries, `Config::from_env` built a single struct from `read_secret(...)`
(the Anthropic API key), `build_postgres_url(...)` (a URL with the
`triage_app` password in it) and ordinary settings. CodeQL's Rust analysis
tainted the whole struct returned through `?`, not just the secret fields,
so reading any setting from `cfg` carried the taint: `cfg.monthly_budget_usd`
into the report text, `cfg.max_templates_per_run` into a printed count,
`cfg.model` and `cfg.max_tokens` into the dry-run line, and in the
collector `cfg.loki_base_url` into the Loki request. None of those lines
printed or sent a secret. But the struct really was a hazard: any future
`{:?}` of `Config`, or a log of it during debugging, would have leaked
both secrets.

**Rationale**:
- **Separate the secrets rather than silence the alerts.** Dismissing
  seven false positives would leave the struct that caused them, and the
  real risk with it. With the secrets in their own struct, `Config`
  holds nothing sensitive and can be logged freely.
- **The `Secret` newtype** (`common/src/secret.rs`) wraps a `String` and:
  - does not implement `Display`, so `{}` doesn't compile;
  - has a `Debug` that prints `Secret([REDACTED])`, so `{:?}`, including
    through a struct that derives `Debug` (both `Secrets` structs do),
    shows no value;
  - does not implement `Clone`, so copies are deliberate;
  - exposes the value only through `expose()`, which is called at exactly
    four places: the `PgPoolOptions::connect` calls in the collector, the
    analyst and `triage-cli`, and the `x-api-key` header.
  `read_secret` and `build_postgres_url` return `Secret` directly, so a
  secret is wrapped from the moment it's read.
- **Behaviour is unchanged.** Same environment variables, same `_FILE`
  handling, same connection strings; `Secrets` is read before `Config`, as
  the secret fields were read first before, so the same missing variable
  produces the same first error.
- **Error messages carry no values.** `read_secret`'s errors name the
  variable and file path, never the contents. That was already true and
  is unchanged.
- **No new crates.** `secrecy` and `zeroize` would add the same guarantees
  plus memory wiping. The newtype is about 20 lines and covers the logging
  and debugging leaks, which are the realistic ones here.

**What it doesn't protect against**:
- **Memory isn't zeroized.** The secret stays in the process's memory
  until it's overwritten, and a core dump or memory read could reveal it.
  Both binaries are short-lived batch jobs running as a non-root user,
  which limits this. Adopting `zeroize` is a possible follow-up if the
  process model changes (for example, a long-running service).
- **`expose()` can still be misused.** A future `println!("{}",
  secrets.database_url.expose())` compiles. The single, greppable accessor
  makes that easy to spot in review, and CodeQL's cleartext-logging query
  would still flag it.

**Accepted risk: Loki over internal HTTP (#2).** `TRIAGE_LOKI_BASE_URL`
defaults to `http://loki:3100`. The collector reaches Loki over the
internal Docker network, Loki has no public route (removed 2026-09-25),
and the request carries no credentials: only the tenant header
`X-Scope-OrgID: fake`. TLS here would protect a read-only query between
two containers on the same host. The alert is dismissed as "won't fix"
with a comment pointing here. Revisit if:
- Loki becomes reachable from off the host's internal networks (a public
  route, a published port, or a Loki on another machine); or
- the request gains credentials (Loki auth, a real tenant secret, a
  token), since those would then cross the network in cleartext.

**Consequences**:
- `Config` in both binaries can be logged or printed for debugging
  without risk.
- Future sensitive-data alerts should be read path first: if the source
  is a `Secret`, the fix is almost always to stop the value reaching the
  sink, not to dismiss.
- Checking `main` for alerts is only meaningful after `main` has been
  analyzed. PR analyses show only alerts on changed lines, so a clean PR
  says nothing about existing code.

## ADR-027: No Prompt Caching for a Once-a-Day Call

**Decision**: Stop setting `cache_control` on the analyst's system prompt.
This supersedes spec §1.1 point 6 ("prompt caching is mandatory") and the
§9 caching bullet, both now marked superseded in `docs/spec.md`.

**Context**: The analyst makes one Messages API call per run, and runs
once a day. Anthropic's default cache lifetime is 5 minutes. Across all 27
recorded calls (2026-09-10 to 2026-09-27) `api_call.cache_read_tokens` is
0: nothing was ever read back. Until 2026-09-27 the system prompt was also
under Haiku 4.5's minimum cacheable size, so caching was silently off.
When the known-patterns file grew past that minimum, the first cache write
appeared (5,389 tokens on run 31). A write is billed at 1.25× the input
rate, so from then on caching only added cost.

**Rationale**:
- Caching pays off only when a later request reuses the prefix within the
  cache lifetime. A single daily call never does, so every write is pure
  overhead.
- The 1-hour cache lifetime doesn't change that. It bills writes at 2× and
  would still expire long before the next day's run.
- Removing the field is simpler than keeping it and explaining why it
  never helps. The test that required it now asserts the opposite: the
  request body contains no `cache_control`.

**Consequences**:
- The cost is roughly $0.10 per run (27 calls, $2.64 total, $0.098
  average). It's driven by the per-run limit on log patterns
  (`TRIAGE_MAX_TEMPLATES_PER_RUN`, default 150) and by `benign` verdicts,
  not by caching.
- The `Usage` parsing, the `api_call` cache columns and the cache rates in
  `cost.rs` stay, so any cache tokens the API ever reports are still
  recorded and costed.
- Revisit if a run starts making more than one call within the cache
  lifetime. That could come from splitting templates across several calls
  instead of capping them, or from a retry loop that resends the same
  system prompt.
