// ==============================================================================
// hash.rs - template_hash computation
// ==============================================================================
// Description: SHA-256 over (service_name, logger_or_module, normalized
//              template), per docs/spec.md §4/§6. Hashing the tuple, not the
//              template text alone, means two structurally identical lines
//              from different services/loggers never collapse to the same
//              hash — an operator marking one template `benign` can't
//              silently suppress an unrelated issue in another service.
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-27
// Version: 0.1.1
// ==============================================================================

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

/// NUL-separated so no combination of field values can collide across the
/// field boundary (e.g. service="a", logger="b|c" vs service="a|b", logger="c").
pub fn template_hash(service_name: &str, logger_or_module: &str, normalized_template: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(service_name.as_bytes());
    hasher.update(b"\0");
    hasher.update(logger_or_module.as_bytes());
    hasher.update(b"\0");
    hasher.update(normalized_template.as_bytes());
    // sha2 0.11's digest type no longer implements LowerHex, so format the
    // bytes directly. Output is unchanged: 64 lowercase hex chars.
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest.iter() {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::template_hash;

    #[test]
    fn different_services_never_collide() {
        let a = template_hash("plex", "app", "worker <NUM> exited");
        let b = template_hash("traefik", "app", "worker <NUM> exited");
        assert_ne!(a, b);
    }

    #[test]
    fn field_boundary_does_not_collide() {
        let a = template_hash("a", "b|c", "tmpl");
        let b = template_hash("a|b", "c", "tmpl");
        assert_ne!(a, b);
    }

    /// Pins the exact output format (64 lowercase hex chars) and value.
    /// template_hash is stored in Postgres and joined against verdicts, so
    /// a dependency bump must not change it. Expected value from Python's
    /// hashlib.sha256(b"plex\0app\0worker <NUM> exited").hexdigest().
    #[test]
    fn known_value_is_stable() {
        assert_eq!(
            template_hash("plex", "app", "worker <NUM> exited"),
            "105e9468b09a52ff4e690c5fdc650a28eada6e2e4ee941b4868cd3b4bb9f7911"
        );
    }

    #[test]
    fn deterministic() {
        let a = template_hash("plex", "app", "worker <NUM> exited");
        let b = template_hash("plex", "app", "worker <NUM> exited");
        assert_eq!(a, b);
    }
}
