// ==============================================================================
// normalize.rs - log-line normalization (redaction-by-structure)
// ==============================================================================
// Description: Reduces a raw log line to a template by replacing variable
//              substrings with typed placeholders, per docs/spec.md §4. This
//              is the security-critical piece backing ADR-016: normalization
//              is structural redaction of known variable shapes, with a
//              best-effort credential/token pass layered on top — not a
//              guarantee that every possible secret shape is caught.
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-25
// Version: 0.3.0
// ==============================================================================

use regex::Regex;
use std::sync::OnceLock;

/// Ordered patterns. Order matters: earlier, more specific patterns must run
/// before later, more general ones (e.g. IPv4 before the trailing decimal-run
/// pattern) or the general pattern swallows the specific one's digits first.
/// MAC runs before IPv6 (spec §4 lists IPv6 first) and before the bare
/// clock pattern: a MAC whose octets are all decimal (`00:11:22:...`) would
/// otherwise have its first three groups read as `hh:mm:ss`.
struct Patterns {
    timestamp: Regex,
    us_datetime: Regex,
    uuid: Regex,
    mac: Regex,
    ipv6: Regex,
    clock: Regex,
    ipv4: Regex,
    email: Regex,
    url: Regex,
    quoted_path: Regex,
    path: Regex,
    hex_run: Regex,
    labeled_pid: Regex,
    number: Regex,
    labeled_secret: Regex,
    cred_prefix: Regex,
    base64_blob: Regex,
}

/// `<IPV4>`/`<IPV6>` (per spec §4) contain digits, so if inserted before the
/// final decimal-run pass, that pass re-consumes the digit inside the
/// placeholder (e.g. "<IPV4>" -> "<IPV<NUM>>"). These digit-free markers
/// stand in during the pipeline and are swapped for the real tokens last.
const IPV4_MARK: &str = "\u{0}IPVFOURMARK\u{0}";
const IPV6_MARK: &str = "\u{0}IPVSIXMARK\u{0}";

fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| Patterns {
        // ISO 8601 / RFC 3339, plus the `YYYY/MM/DD hh:mm:ss` variant that
        // nginx's error log and Liquidsoap emit, and the Common Log Format
        // `DD/Mon/YYYY:hh:mm:ss +zzzz` of access logs (Traefik, nginx).
        // Without the slash forms the date half fell to the path pattern
        // (`<NUM><PATH>`).
        timestamp: Regex::new(
            r"\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\b\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}(?: [+-]\d{4})?",
        )
        .unwrap(),
        // US `MM/DD/YYYY, h:mm:ss [AM|PM]` (NestJS, many JS loggers). The
        // time part is required, and group 1 must not be `/` or a digit, so
        // a date-shaped run of path segments (`/backups/12/05/2024/x`) is
        // left for the path pattern rather than split open by this one.
        us_datetime: Regex::new(
            r"(^|[^/\d])\d{1,2}/\d{1,2}/\d{4},?\s+\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?(?:\s?[AaPp][Mm]\b)?",
        )
        .unwrap(),
        uuid: Regex::new(
            r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        )
        .unwrap(),
        mac: Regex::new(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b").unwrap(),
        // A valid IPv6 address has either all eight groups or a `::`. The
        // old 2-to-7-group shape also matched any `hh:mm:ss` clock value
        // and labelled it <IPV6>. The middle alternative now takes the
        // groups after an interior `::` (`2001:db8::1`), which it used to
        // leave behind for the number pass.
        ipv6: Regex::new(
            r"(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,5}\b)?|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}\b",
        )
        .unwrap(),
        // Bare clock value with no date (Redis, slskd `[hh:mm:ss INF]`,
        // durations). Runs after IPv6 so a real address claims its digits
        // first.
        clock: Regex::new(r"\b\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?\b").unwrap(),
        ipv4: Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b",
        )
        .unwrap(),
        email: Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap(),
        url: Regex::new(r#"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s"'<>]+"#).unwrap(),
        // A quoted absolute path, taken whole up to the closing quote so
        // that spaces inside it (`"/music/Pink Floyd/The Wall/01.flac"`)
        // don't end the match. The unquoted pattern below stops at the
        // first space and leaves the rest of the path as template text,
        // which made every media file its own template. The double-quote
        // arm also accepts JSON-escaped `\"...\"`.
        quoted_path: Regex::new(
            r#"(\\?")/[^"\\\n]*/[^"\\\n]*(\\?")|(')/[^'\n]*/[^'\n]*(')"#,
        )
        .unwrap(),
        path: Regex::new(r"(?:/[\w.\-]+){2,}").unwrap(),
        hex_run: Regex::new(r"(?i)\b[0-9a-f]{8,}\b").unwrap(),
        labeled_pid: Regex::new(r"(?i)(pid=|pid |\[pid:\s*)(\d+)").unwrap(),
        number: Regex::new(r"\d+").unwrap(),
        // `key=value`/`key: value` where key names a credential — covers
        // arbitrary secret shapes a structural pattern can't anticipate
        // (e.g. `password=hunter2SuperSecret`), at the cost of only firing
        // when the log line actually labels the field. Value stops at
        // whitespace/comma/semicolon/quote so it doesn't eat the rest of
        // the line.
        labeled_secret: Regex::new(
            r#"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|authorization)(\s*[:=]\s*)"?([^\s,;"']+)"?"#,
        )
        .unwrap(),
        // Known credential ID prefixes/formats: AWS access key ID, GitHub
        // fine-grained/classic PATs, Anthropic and OpenAI-style API keys.
        // Unlike labeled_secret these fire with no surrounding label —
        // the prefix alone is distinctive enough in practice.
        cred_prefix: Regex::new(
            r"\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,255}\b|\bsk-ant-[A-Za-z0-9_-]{20,}\b|\bsk-[A-Za-z0-9]{32,}\b",
        )
        .unwrap(),
        // Long unbroken base64-alphabet run (e.g. a Basic-auth credential,
        // a bearer token, a base64-encoded secret with no distinctive
        // prefix). A 20-24 char floor (5 full groups, +1 possibly-padded
        // group) is close to the shortest a realistic `user:pass`-shaped
        // Basic credential encodes to, and still keeps this well clear of
        // the hyphen/underscore/dot-separated identifiers (container
        // names, version strings) that are common and legitimate in these
        // logs — those never fall in this alphabet regardless of length.
        // An entropy/mixed-class alternative was measured and rejected for
        // over-redacting exactly those identifiers; see ADR-016.
        // No trailing \b: a `=` padding char is non-word, so a boundary
        // check right after it (followed by whitespace/EOL, also
        // non-word) never matches — the character class itself already
        // bounds the match correctly without one.
        base64_blob: Regex::new(r"\b(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
            .unwrap(),
    })
}

/// Reduce a raw log line to a normalized template. See docs/spec.md §4 for
/// the pattern order and rationale, and §8 for the redaction test suite that
/// enforces this function never leaks an IP/email/UUID/path/hex secret.
pub fn normalize(line: &str) -> String {
    let p = patterns();
    let s = p.timestamp.replace_all(line, "<TIMESTAMP>");
    let s = p
        .us_datetime
        .replace_all(&s, |caps: &regex::Captures| format!("{}<TIMESTAMP>", &caps[1]));
    let s = p.uuid.replace_all(&s, "<UUID>");
    let s = p.mac.replace_all(&s, "<MAC>");
    let s = p.ipv6.replace_all(&s, IPV6_MARK);
    let s = p.clock.replace_all(&s, "<TIMESTAMP>");
    let s = p.ipv4.replace_all(&s, IPV4_MARK);
    let s = p.email.replace_all(&s, "<EMAIL>");
    let s = p.url.replace_all(&s, "<URL>");
    let s = p.quoted_path.replace_all(&s, |caps: &regex::Captures| {
        let open = caps.get(1).or_else(|| caps.get(3)).map_or("", |m| m.as_str());
        let close = caps.get(2).or_else(|| caps.get(4)).map_or("", |m| m.as_str());
        format!("{open}<PATH>{close}")
    });
    let s = p.path.replace_all(&s, "<PATH>");
    // Credential passes must run before hex_run/number: labeled_secret and
    // cred_prefix values often contain digits, and hex_run/number would
    // otherwise consume that digit evidence (or half the value) first,
    // leaving the alphabetic remainder — exactly the leak in Finding 2.
    let s = p.labeled_secret.replace_all(&s, |caps: &regex::Captures| {
        format!("{}{}<SECRET>", &caps[1], &caps[2])
    });
    let s = p.cred_prefix.replace_all(&s, "<SECRET>");
    let s = p.base64_blob.replace_all(&s, "<SECRET>");
    let s = p.hex_run.replace_all(&s, "<HEX>");
    let s = p
        .labeled_pid
        .replace_all(&s, |caps: &regex::Captures| format!("{}<PID>", &caps[1]));
    let s = p.number.replace_all(&s, "<NUM>");
    s.replace(IPV6_MARK, "<IPV6>").replace(IPV4_MARK, "<IPV4>")
}

#[cfg(test)]
mod tests {
    use super::normalize;
    use proptest::prelude::*;

    #[test]
    fn timestamp_and_ipv4_and_email() {
        let line = "2026-09-09T12:00:00Z ERROR db connect to 10.0.0.5 failed for user a@b.com";
        let out = normalize(line);
        assert!(!out.contains("2026"));
        assert!(!out.contains("10.0.0.5"));
        assert!(!out.contains("a@b.com"));
        assert!(out.contains("<TIMESTAMP>"));
        assert!(out.contains("<IPV4>"));
        assert!(out.contains("<EMAIL>"));
    }

    #[test]
    fn uuid_not_swallowed_by_hex_run() {
        let line = "request 123e4567-e89b-12d3-a456-426614174000 failed";
        let out = normalize(line);
        assert_eq!(out, "request <UUID> failed");
    }

    #[test]
    fn ipv4_not_treated_as_bare_numbers() {
        let line = "connect 192.168.1.1 refused";
        assert_eq!(normalize(line), "connect <IPV4> refused");
    }

    #[test]
    fn absolute_path_requires_two_segments() {
        assert_eq!(
            normalize("reading /etc/passwd now"),
            "reading <PATH> now"
        );
        // single segment: not treated as a path, falls through to plain text
        assert_eq!(normalize("go /home now"), "go /home now");
    }

    #[test]
    fn labeled_pid_vs_bare_number() {
        assert_eq!(normalize("worker pid=1234 exited"), "worker pid=<PID> exited");
        assert_eq!(normalize("worker [pid: 1234] exited"), "worker [pid: <PID>] exited");
        // bare number with no PID label falls through to <NUM>, never <PID>
        assert_eq!(normalize("retry count 1234"), "retry count <NUM>");
    }

    #[test]
    fn mac_address_redacted() {
        assert_eq!(
            normalize("link up 00:1a:2b:3c:4d:5e detected"),
            "link up <MAC> detected"
        );
    }

    #[test]
    fn url_redacted() {
        assert_eq!(
            normalize("GET https://api.example.com/v1/users?id=5 200"),
            "GET <URL> <NUM>"
        );
    }

    /// Bare `hh:mm:ss` used to satisfy the 2-to-7-group IPv6 shape and come
    /// out as `<IPV6>`, which told the analyst an address was involved.
    #[test]
    fn clock_time_is_timestamp_not_ipv6() {
        assert_eq!(normalize("[22:18:42 INF] started"), "[<TIMESTAMP> INF] started");
        assert_eq!(normalize("took 0:05:12.345 total"), "took <TIMESTAMP> total");
    }

    #[test]
    fn real_ipv6_still_redacted() {
        assert_eq!(normalize("from 2001:db8::1 port 80"), "from <IPV6> port <NUM>");
        assert_eq!(normalize("peer fe80:0:0:0:202:b3ff:fe1e:8329 up"), "peer <IPV6> up");
        assert_eq!(normalize("bind ::1 ok"), "bind <IPV6> ok");
        assert_eq!(normalize("net 2001:db8:: routed"), "net <IPV6> routed");
    }

    #[test]
    fn all_decimal_mac_not_read_as_clock() {
        assert_eq!(normalize("link 00:11:22:33:44:55 up"), "link <MAC> up");
    }

    #[test]
    fn slash_dated_timestamps() {
        // Liquidsoap / nginx error log
        assert_eq!(
            normalize("2026/09/24 08:53:42 [next_song:3] ready"),
            "<TIMESTAMP> [next_song:<NUM>] ready"
        );
        // NestJS
        assert_eq!(normalize("- 09/09/2026, 3:02:01 PM LOG"), "- <TIMESTAMP> LOG");
        // Common Log Format (Traefik access log)
        assert_eq!(
            normalize(r#"- - [24/Sep/2026:08:53:42 +0000] "GET / HTTP/1.1""#),
            r#"- - [<TIMESTAMP>] "GET / HTTP/<NUM>.<NUM>""#
        );
    }

    /// A path whose segments happen to look like a date must still be
    /// redacted as a path, not split into leaked segments around a
    /// `<TIMESTAMP>`.
    #[test]
    fn date_shaped_path_stays_a_path() {
        assert_eq!(
            normalize("dump /backups/12/05/2024 10:00:00 done"),
            "dump <PATH> <TIMESTAMP> done"
        );
    }

    /// Liquidsoap logs one line per track with the full media path. The
    /// unquoted path pattern stopped at the first space, so the rest of
    /// the artist/album/title stayed in the template and every song became
    /// its own template.
    #[test]
    fn quoted_path_with_spaces_redacted_whole() {
        assert_eq!(
            normalize(r#"Prepared "/var/music/Bobby McFerrin/Simple Pleasures/04 - Don't Worry.flac" (RID 6880)."#),
            r#"Prepared "<PATH>" (RID <NUM>)."#
        );
        assert_eq!(
            normalize(r#"{"file":\"/srv/My Files/a b.txt\"}"#),
            r#"{"file":\"<PATH>\"}"#
        );
        assert_eq!(normalize("open '/srv/My Files/a b.txt' failed"), "open '<PATH>' failed");
        // single segment in quotes: not a path, same as the unquoted rule
        assert_eq!(normalize(r#"cd "/tmp dir" now"#), r#"cd "/tmp dir" now"#);
    }

    /// An external review demonstrated the digit-only pass leaving the
    /// alphabetic body of a credential intact (`password=hunter2SuperSecret`
    /// -> `password=hunter<NUM>SuperSecret`). Locks in the fix from
    /// ADR-016's option (a).
    #[test]
    fn labeled_credential_redacted() {
        assert_eq!(normalize("password=hunter2SuperSecret"), "password=<SECRET>");
        assert_eq!(normalize("token: abc123XYZsecret"), "token: <SECRET>");
    }

    #[test]
    fn known_credential_prefix_redacted() {
        assert_eq!(
            normalize("key AKIAIOSFODNN7EXAMPLE leaked"),
            "key <SECRET> leaked"
        );
        assert_eq!(
            normalize("using ghp_16C7e42F292c6912E7710c83B1a2C3d4E5f6"),
            "using <SECRET>"
        );
        assert_eq!(
            normalize("ANTHROPIC_API_KEY=sk-ant-api03-TESTFIXTURETESTFIXTURETEST"),
            "ANTHROPIC_API_KEY=<SECRET>"
        );
    }

    #[test]
    fn long_base64_blob_redacted() {
        // base64("not-a-real-secret-fixture-val") — an unlabeled,
        // unprefixed secret shape, e.g. a Basic-auth credential.
        assert_eq!(
            normalize("Basic bm90LWEtcmVhbC1zZWNyZXQtZml4dHVyZS12YWw="),
            "Basic <SECRET>"
        );
    }

    /// Measured against a rejected entropy-based alternative before choosing
    /// the curated patterns above (ADR-016): that alternative collapsed
    /// exactly these into `<TOKEN>`, destroying the service-identifying text
    /// an analyst needs. These stay legible under the chosen design.
    #[test]
    fn realistic_identifiers_not_over_redacted() {
        assert_eq!(
            normalize("container=authentik-worker-1"),
            "container=authentik-worker-<NUM>"
        );
        assert_eq!(
            normalize("traefik_v3.1.2 healthy"),
            "traefik_v<NUM>.<NUM>.<NUM> healthy"
        );
        assert_eq!(
            normalize("worker-pool-3a started"),
            "worker-pool-<NUM>a started"
        );
    }

    proptest! {
        #[test]
        fn never_leaks_labeled_secret_value(value in "[A-Za-z0-9]{8,20}") {
            let line = format!("password={value}");
            let out = normalize(&line);
            prop_assert!(!out.contains(&value));
            prop_assert!(out.contains("<SECRET>"));
        }

        #[test]
        fn never_leaks_email_shape(user in "[a-z]{3,10}", domain in "[a-z]{3,10}") {
            let line = format!("user {}@{}.com logged in", user, domain);
            let out = normalize(&line);
            prop_assert!(!out.contains('@'));
        }

        #[test]
        fn quoted_path_never_leaks_segments(
            a in "[A-Za-z]{3,8}( [A-Za-z]{3,8}){0,3}",
            b in "[A-Za-z0-9 ._-]{1,30}[A-Za-z0-9]",
        ) {
            let line = format!("Prepared \"/music/{a}/{b}.flac\" done");
            let out = normalize(&line);
            prop_assert_eq!(out, "Prepared \"<PATH>\" done");
        }

        #[test]
        fn clock_never_labeled_ipv6(h in 0u8..24, m in 0u8..60, s in 0u8..60) {
            let line = format!("at {h:02}:{m:02}:{s:02} ok");
            prop_assert_eq!(normalize(&line), "at <TIMESTAMP> ok");
        }

        #[test]
        fn never_leaks_ipv4_shape(a in 0u8..255, b in 0u8..255, c in 0u8..255, d in 0u8..255) {
            let line = format!("src {}.{}.{}.{} dst 0.0.0.0", a, b, c, d);
            let out = normalize(&line);
            // every dotted-quad substring must have been replaced
            let needle = format!("{}.{}.{}.{}", a, b, c, d);
            prop_assert!(!out.contains(&needle));
        }
    }
}
