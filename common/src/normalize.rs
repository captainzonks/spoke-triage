// ==============================================================================
// normalize.rs - log-line normalization (redaction-by-structure)
// ==============================================================================
// Description: Reduces a raw log line to a template by replacing variable
//              substrings with typed placeholders, per docs/spec.md §4. This
//              is the security-critical piece backing ADR-016: normalization
//              is a structural redaction mechanism, not a blocklist filter.
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-10
// Version: 0.1.2
// ==============================================================================

use regex::Regex;
use std::sync::OnceLock;

/// Ordered patterns. Order matters: earlier, more specific patterns must run
/// before later, more general ones (e.g. IPv4 before the trailing decimal-run
/// pattern) or the general pattern swallows the specific one's digits first.
/// MAC runs before IPv6 (spec §4 lists IPv6 first) because the general IPv6
/// shape — 2-to-7 colon-separated hex groups — also matches a bare MAC
/// address (six 2-hex-digit groups); MAC's exact 6x2-hex-digit shape is
/// unambiguous and must claim the match first.
struct Patterns {
    timestamp: Regex,
    uuid: Regex,
    mac: Regex,
    ipv6: Regex,
    ipv4: Regex,
    email: Regex,
    url: Regex,
    path: Regex,
    hex_run: Regex,
    labeled_pid: Regex,
    number: Regex,
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
        timestamp: Regex::new(
            r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
        )
        .unwrap(),
        uuid: Regex::new(
            r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        )
        .unwrap(),
        mac: Regex::new(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b").unwrap(),
        ipv6: Regex::new(
            r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,7}:|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}\b",
        )
        .unwrap(),
        ipv4: Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b",
        )
        .unwrap(),
        email: Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap(),
        url: Regex::new(r#"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s"'<>]+"#).unwrap(),
        path: Regex::new(r"(?:/[\w.\-]+){2,}").unwrap(),
        hex_run: Regex::new(r"(?i)\b[0-9a-f]{8,}\b").unwrap(),
        labeled_pid: Regex::new(r"(?i)(pid=|pid |\[pid:\s*)(\d+)").unwrap(),
        number: Regex::new(r"\d+").unwrap(),
    })
}

/// Reduce a raw log line to a normalized template. See docs/spec.md §4 for
/// the pattern order and rationale, and §8 for the redaction test suite that
/// enforces this function never leaks an IP/email/UUID/path/hex secret.
pub fn normalize(line: &str) -> String {
    let p = patterns();
    let s = p.timestamp.replace_all(line, "<TIMESTAMP>");
    let s = p.uuid.replace_all(&s, "<UUID>");
    let s = p.mac.replace_all(&s, "<MAC>");
    let s = p.ipv6.replace_all(&s, IPV6_MARK);
    let s = p.ipv4.replace_all(&s, IPV4_MARK);
    let s = p.email.replace_all(&s, "<EMAIL>");
    let s = p.url.replace_all(&s, "<URL>");
    let s = p.path.replace_all(&s, "<PATH>");
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

    proptest! {
        #[test]
        fn never_leaks_email_shape(user in "[a-z]{3,10}", domain in "[a-z]{3,10}") {
            let line = format!("user {}@{}.com logged in", user, domain);
            let out = normalize(&line);
            prop_assert!(!out.contains('@'));
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
