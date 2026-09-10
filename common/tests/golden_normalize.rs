// ==============================================================================
// golden_normalize.rs - normalization golden tests
// ==============================================================================
// Description: Exact input -> expected-template pairs for normalize(), per
//              docs/spec.md §8 ("golden tests... seed from exemplars already
//              flowing through spoke_log_analysis.sh today"). The hand-written
//              unit tests in common/src/normalize.rs cover one pattern each in
//              isolation; this file captures whole real log lines exactly as
//              emitted by live services on a real Spoke deployment (Traefik,
//              CrowdSec, Alloy, Authentik, Redis, Immich/NestJS), covering
//              the case the unit tests can't: multiple patterns colliding in
//              one line, and formats the normalizer was never specifically
//              designed for.
//
//              Provenance: captured via `docker logs` on 2026-09-09 from
//              traefik, crowdsec, alloy, authentik-worker, redis, and
//              immich-server. Two fields were genericized before committing —
//              a real Authentik forward-auth provider display name (site
//              inventory, not a secret) swapped for "Example Forward Auth",
//              and a real Authentik outpost UUID swapped for the standard
//              OpenAPI example UUID (3fa85f64-...) — everything else,
//              including timestamps and formatting, is verbatim.
//
//              Two lines below (Redis, NestJS) demonstrate a known quirk, not
//              a defect: bare `HH:MM:SS` time-of-day (no ISO date component,
//              e.g. Redis's own log format) and slash-delimited `MM/DD/YYYY`
//              dates are outside the ISO-8601/RFC-3339 timestamp pattern
//              (spec §4 item 1) and get opportunistically consumed by the
//              IPv6 or path patterns instead (three colon-separated hex-safe
//              groups is structurally indistinguishable from IPv6; two
//              slash-delimited segments is structurally indistinguishable
//              from an absolute path). The redaction guarantee still holds —
//              nothing raw survives, the line still collapses to a stable
//              template — the placeholder is just mislabeled. Locked in here
//              rather than "fixed", since the fix scope (a real date/time
//              grammar) is outside spec §4's stated pattern list.
// Author: Matt Barham
// Created: 2026-09-09
// Version: 0.1.0
// ==============================================================================

use spoke_triage_common::normalize::normalize;

/// (input, expected_template) — see file header for provenance.
const GOLDEN: &[(&str, &str)] = &[
    // Traefik: plain shutdown line.
    (
        "2026-09-09T12:45:40-06:00 INF Shutting down",
        "<TIMESTAMP> INF Shutting down",
    ),
    // CrowdSec: the literal word "signal" with no SIGTERM/SIGKILL keyword —
    // an evidence-rule anti-hallucination case (spec §7), not a crash.
    (
        r#"time="2026-09-09T15:28:47-06:00" level=info msg="received signal for http_crowdsec config" @module=http-plugin module=plugin"#,
        r#"time="<TIMESTAMP>" level=info msg="received signal for http_crowdsec config" @module=http-plugin module=plugin"#,
    ),
    // Alloy: `component_path=/` is a single slash, not two path segments —
    // correctly left unredacted (spec §4 item 8 requires >= 2 segments).
    (
        r#"ts=2026-09-09T18:44:36.369828444Z level=info msg="loki.source.file component shutting down, stopping sources and positions file" component_path=/ component_id=loki.source.file.system_files"#,
        r#"ts=<TIMESTAMP> level=info msg="loki.source.file component shutting down, stopping sources and positions file" component_path=/ component_id=loki.source.file.system_files"#,
    ),
    // Authentik: the exact "authentik.outposts.signals" logger + "signals"
    // pub/sub wording the known_patterns.md.example anti-hallucination
    // section calls out by name — this must never read as a Unix signal.
    (
        r#"{"domain_url": null, "event": "Provider changed, rebuilding permissions and sending update", "level": "info", "logger": "authentik.outposts.signals", "outpost": "authentik Embedded Outpost", "pid": 19, "provider": "Example Forward Auth", "schema_name": "public", "timestamp": "2026-09-09T14:57:07.388081"}"#,
        r#"{"domain_url": null, "event": "Provider changed, rebuilding permissions and sending update", "level": "info", "logger": "authentik.outposts.signals", "outpost": "authentik Embedded Outpost", "pid": <NUM>, "provider": "Example Forward Auth", "schema_name": "public", "timestamp": "<TIMESTAMP>"}"#,
    ),
    // Authentik: JSON `"pid":8` (no space/equals after the key) must NOT
    // match the labeled-PID pattern — only `pid=`/`pid `/`[pid:` count
    // (spec §4 item 10). Falls through to plain <NUM>, same as any other
    // integer field.
    (
        r#"{"filename":"src/outpost/event.rs","level":"info","line_number":343,"pid":8,"target":"authentik::outpost::event","thread_id":"ThreadId(3)","thread_name":"tokio-0","timestamp":"2026-09-09T17:43:49.947993","attempt":4,"delay":16,"event":"reconnecting websocket in 16s..."}"#,
        r#"{"filename":"src<PATH>","level":"info","line_number":<NUM>,"pid":<NUM>,"target":"authentik::outpost::event","thread_id":"ThreadId(<NUM>)","thread_name":"tokio-<NUM>","timestamp":"<TIMESTAMP>","attempt":<NUM>,"delay":<NUM>,"event":"reconnecting websocket in <NUM>s..."}"#,
    ),
    // Authentik: the literal "reconnecting websocket" / "connected to
    // websocket" pair the known_patterns.md.example WebSocket-reconnection
    // example describes in prose — real UUID swapped for a fake one (see
    // file header) before committing.
    (
        r#"{"filename":"src/outpost/event.rs","level":"info","line_number":213,"pid":8,"target":"authentik::outpost::event","thread_id":"ThreadId(3)","thread_name":"tokio-0","timestamp":"2026-09-09T17:44:07.666503","event":"connected to websocket","outpost":"3fa85f64-5717-4562-b3fc-2c963f66afa6"}"#,
        r#"{"filename":"src<PATH>","level":"info","line_number":<NUM>,"pid":<NUM>,"target":"authentik::outpost::event","thread_id":"ThreadId(<NUM>)","thread_name":"tokio-<NUM>","timestamp":"<TIMESTAMP>","event":"connected to websocket","outpost":"<UUID>"}"#,
    ),
    // Redis: `pid=7` labeled-PID vs. `commit=00000000` (8 hex chars, hits
    // the hex-run pattern) in the same line — and the known bare-time-of-day
    // quirk from the file header (`22:18:42.696` -> `<IPV6>.<NUM>`).
    (
        "7:C 09 Sep 2026 22:18:42.696 * Redis version=8.4.0, bits=64, commit=00000000, modified=1, pid=7, just started",
        "<NUM>:C <NUM> Sep <NUM> <IPV6>.<NUM> * Redis version=<NUM>.<NUM>.<NUM>, bits=<NUM>, commit=<HEX>, modified=<NUM>, pid=<PID>, just started",
    ),
    // NestJS/Immich: raw ANSI color codes survive normalize() untouched (not
    // a redaction target — not sensitive), and the `MM/DD/YYYY, H:MM:SS PM`
    // timestamp hits the known slash/colon quirk from the file header
    // instead of <TIMESTAMP>. Nothing raw survives either way.
    (
        "\x1b[32m[Nest] 8  - \x1b[39m09/09/2026, 3:02:01 PM \x1b[32m    LOG\x1b[39m \x1b[33m[Microservices:WebsocketRepository]\x1b[39m \x1b[32mInitialized websocket server\x1b[39m",
        "\x1b[<NUM>m[Nest] <NUM>  - \x1b[<NUM>m<NUM><PATH>, <IPV6> PM \x1b[<NUM>m    LOG\x1b[<NUM>m \x1b[<NUM>m[Microservices:WebsocketRepository]\x1b[<NUM>m \x1b[<NUM>mInitialized websocket server\x1b[<NUM>m",
    ),
];

#[test]
fn golden_corpus_matches_exactly() {
    for (input, expected) in GOLDEN {
        let actual = normalize(input);
        assert_eq!(
            &actual, expected,
            "\ninput:    {input}\nexpected: {expected}\nactual:   {actual}\n"
        );
    }
}

/// The UUID line specifically: confirm the fake stand-in UUID committed to
/// this corpus (see file header) is actually consumed by normalize(), not
/// merely absent from the hardcoded expected string above.
#[test]
fn golden_uuid_line_is_actually_redacted() {
    let input = GOLDEN[5].0;
    assert!(!normalize(input).contains("3fa85f64-5717-4562-b3fc-2c963f66afa6"));
}
