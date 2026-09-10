// ==============================================================================
// schema.rs - triage_report tool schema
// ==============================================================================
// Description: The forced-tool-use input_schema from docs/spec.md §5. Note
//              `status` (new/recurring/escalating/resolved) is deliberately
//              absent — it's computed by triage-collector's history, never
//              asked of the model (spec §5).
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-09
// Version: 0.1.0
// ==============================================================================

use serde_json::{json, Value};

pub const TRIAGE_REPORT_TOOL_NAME: &str = "triage_report";

pub fn triage_report_tool() -> Value {
    json!({
        "name": TRIAGE_REPORT_TOOL_NAME,
        "description": "Record the triage report for this run's aggregated log templates. Call this exactly once with the complete report: a short overall summary, the total event count, an overall health verdict, and one finding per template that represents a genuine issue (omit templates that are routine/benign — an empty findings array is a valid, good report).",
        "strict": true,
        "input_schema": {
            "type": "object",
            "additionalProperties": false,
            "required": ["summary", "total_events", "health", "findings"],
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "1-3 sentence overview of this run's log activity."
                },
                "total_events": {
                    "type": "integer",
                    "description": "Sum of counts across all templates considered in this run."
                },
                "health": {
                    "type": "string",
                    "enum": ["healthy", "degraded", "critical"]
                },
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": [
                            "template_hash",
                            "severity",
                            "service",
                            "issue",
                            "count",
                            "first_seen",
                            "last_seen",
                            "recommendation"
                        ],
                        "properties": {
                            "template_hash": {
                                "type": "string",
                                "description": "The template_hash this finding is about, copied verbatim from the input data."
                            },
                            "severity": {
                                "type": "string",
                                "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                            },
                            "service": {
                                "type": "string",
                                "description": "service_name copied verbatim from the input data."
                            },
                            "issue": {
                                "type": "string",
                                "description": "What's happening. For any claim of a process signal, crash, shutdown, restart, OOM, or worker recycling, must include a verbatim >=20 char fragment from an exemplar line per the Evidence Rules."
                            },
                            "count": {
                                "type": "integer",
                                "description": "Occurrence count, copied verbatim from the input data."
                            },
                            "first_seen": {
                                "type": "string",
                                "description": "Copied verbatim from the input data."
                            },
                            "last_seen": {
                                "type": "string",
                                "description": "Copied verbatim from the input data."
                            },
                            "recommendation": {
                                "type": "string",
                                "description": "A specific remediation step for CRITICAL/HIGH findings. May be empty for LOW/INFO."
                            }
                        }
                    }
                }
            }
        }
    })
}
