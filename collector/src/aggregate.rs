// ==============================================================================
// aggregate.rs - normalize, identify, and aggregate Loki results by template
// ==============================================================================
// Description: Turns raw Loki query_range streams into per-template
//              aggregates (docs/spec.md §3.1 steps 2-3, §4). service_name
//              comes from the compose_service/container_name stream labels
//              (see appdata/alloy/config/config.alloy in a typical Spoke
//              deployment — Alloy did not promote per-container identity to
//              stream labels until this was fixed alongside this collector;
//              job="docker" logs used to collapse into one undifferentiated
//              stream). System-log
//              (job="system") lines carry no such label since they aren't
//              containers, so service_name there is read from the syslog
//              header's program name instead.
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-09
// Version: 0.1.0
// ==============================================================================

use crate::loki::Stream;
use chrono::{DateTime, Utc};
use regex::Regex;
use spoke_triage_common::{hash::template_hash, normalize::normalize};
use std::collections::HashMap;
use std::sync::OnceLock;

pub struct AggregatedTemplate {
    pub template_hash: String,
    pub service_name: String,
    pub logger: String,
    pub template_text: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub count: i64,
    pub exemplar_lines: Vec<String>,
}

/// Combines every severity bucket's results into one map keyed by
/// template_hash. Buckets are not mutually exclusive (a line can match both
/// a keyword bucket and a level bucket) — collapsing them here is a dedup
/// improvement over the original script's per-bucket report sections, not a
/// data-loss risk, since the count still reflects every match.
pub fn aggregate(streams_by_bucket: &[(&str, Vec<Stream>)], exemplar_limit: usize) -> Vec<AggregatedTemplate> {
    let mut by_hash: HashMap<String, AggregatedTemplate> = HashMap::new();

    for (_bucket, streams) in streams_by_bucket {
        for stream in streams {
            let job = stream.stream.get("job").map(String::as_str).unwrap_or("");
            let (service_name, logger) = extract_identity(job, &stream.stream);

            for entry in &stream.values {
                let (Some(ts_ns), Some(line)) = (entry.first(), entry.get(1)) else {
                    continue;
                };
                let Some(seen_at) = parse_loki_timestamp(ts_ns) else {
                    continue;
                };

                let (service_name, logger) = if job == "system" {
                    (
                        extract_syslog_program(line).unwrap_or_else(|| "system".to_string()),
                        logger.clone().unwrap_or_default(),
                    )
                } else {
                    (
                        service_name.clone(),
                        logger.clone().or_else(|| extract_json_logger(line)).unwrap_or_default(),
                    )
                };
                let template_text = normalize(line);
                let hash = template_hash(&service_name, &logger, &template_text);

                by_hash
                    .entry(hash.clone())
                    .and_modify(|t| {
                        t.count += 1;
                        if seen_at < t.first_seen {
                            t.first_seen = seen_at;
                        }
                        if seen_at > t.last_seen {
                            t.last_seen = seen_at;
                        }
                        if t.exemplar_lines.len() < exemplar_limit && !t.exemplar_lines.contains(line) {
                            t.exemplar_lines.push(line.clone());
                        }
                    })
                    .or_insert_with(|| AggregatedTemplate {
                        template_hash: hash,
                        service_name: service_name.clone(),
                        logger: logger.clone(),
                        template_text: template_text.clone(),
                        first_seen: seen_at,
                        last_seen: seen_at,
                        count: 1,
                        exemplar_lines: vec![line.clone()],
                    });
            }
        }
    }

    by_hash.into_values().collect()
}

/// Returns (service_name, logger). logger is None for docker streams — it's
/// resolved per-line in `aggregate` since it can vary line-to-line within
/// the same container (different loggers in the same process).
fn extract_identity(job: &str, labels: &HashMap<String, String>) -> (String, Option<String>) {
    if job == "system" {
        // service_name resolved per-line from the syslog header; logger is a
        // fixed marker since syslog has no finer-grained module concept.
        return (String::new(), Some("syslog".to_string()));
    }

    let service_name = labels
        .get("compose_service")
        .or_else(|| labels.get("container_name"))
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    (service_name, None)
}

fn extract_json_logger(line: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let obj = value.as_object()?;
    for key in ["logger", "target", "logger_name", "module"] {
        if let Some(s) = obj.get(key).and_then(|v| v.as_str()) {
            return Some(s.to_string());
        }
    }
    None
}

fn syslog_program_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\S+\s+\d+\s+[\d:]+\s+\S+\s+([\w./-]+?)(?:\[\d+\])?:").unwrap())
}

fn extract_syslog_program(line: &str) -> Option<String> {
    syslog_program_regex()
        .captures(line)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

fn parse_loki_timestamp(ns_str: &str) -> Option<DateTime<Utc>> {
    let ns: i64 = ns_str.parse().ok()?;
    DateTime::from_timestamp(ns / 1_000_000_000, (ns % 1_000_000_000) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(job: &str, extra: &[(&str, &str)], values: Vec<(&str, &str)>) -> Stream {
        let mut labels = HashMap::new();
        labels.insert("job".to_string(), job.to_string());
        for (k, v) in extra {
            labels.insert(k.to_string(), v.to_string());
        }
        Stream {
            stream: labels,
            values: values
                .into_iter()
                .map(|(ts, line)| vec![ts.to_string(), line.to_string()])
                .collect(),
        }
    }

    #[test]
    fn docker_service_name_from_compose_service_label() {
        let streams = vec![(
            "errors",
            vec![stream(
                "docker",
                &[("compose_service", "plex")],
                vec![("1000000000000000000", r#"{"logger":"plex.transcode","event":"worker 42 exited"}"#)],
            )],
        )];
        let agg = aggregate(&streams, 3);
        assert_eq!(agg.len(), 1);
        assert_eq!(agg[0].service_name, "plex");
        assert_eq!(agg[0].logger, "plex.transcode");
    }

    #[test]
    fn different_services_same_template_never_collapse() {
        let streams = vec![(
            "errors",
            vec![
                stream(
                    "docker",
                    &[("compose_service", "plex")],
                    vec![("1000000000000000000", r#"{"logger":"app","event":"worker 1 exited"}"#)],
                ),
                stream(
                    "docker",
                    &[("compose_service", "traefik")],
                    vec![("1000000000000000000", r#"{"logger":"app","event":"worker 1 exited"}"#)],
                ),
            ],
        )];
        let agg = aggregate(&streams, 3);
        assert_eq!(agg.len(), 2);
        assert_ne!(agg[0].template_hash, agg[1].template_hash);
    }

    #[test]
    fn repeated_lines_aggregate_into_one_template_with_count() {
        let streams = vec![(
            "errors",
            vec![stream(
                "docker",
                &[("compose_service", "plex")],
                vec![
                    ("1000000000000000000", r#"{"logger":"app","event":"conn 10.0.0.1 failed"}"#),
                    ("1000000001000000000", r#"{"logger":"app","event":"conn 10.0.0.2 failed"}"#),
                ],
            )],
        )];
        let agg = aggregate(&streams, 3);
        assert_eq!(agg.len(), 1);
        assert_eq!(agg[0].count, 2);
        assert_eq!(agg[0].exemplar_lines.len(), 2);
    }

    #[test]
    fn exemplar_lines_bounded_by_limit() {
        let values: Vec<(&str, &str)> = vec![
            ("1000000000000000000", r#"{"logger":"app","event":"retry 1"}"#),
            ("1000000001000000000", r#"{"logger":"app","event":"retry 2"}"#),
            ("1000000002000000000", r#"{"logger":"app","event":"retry 3"}"#),
            ("1000000003000000000", r#"{"logger":"app","event":"retry 4"}"#),
        ];
        let streams = vec![("errors", vec![stream("docker", &[("compose_service", "plex")], values)])];
        let agg = aggregate(&streams, 2);
        assert_eq!(agg[0].count, 4);
        assert_eq!(agg[0].exemplar_lines.len(), 2);
    }

    #[test]
    fn system_service_name_from_syslog_program() {
        assert_eq!(extract_syslog_program("Sep  9 22:10:00 myhost kea-dhcp6[1234]: lease renewed"), Some("kea-dhcp6".to_string()));
        assert_eq!(extract_syslog_program("not a syslog line"), None);
    }
}
