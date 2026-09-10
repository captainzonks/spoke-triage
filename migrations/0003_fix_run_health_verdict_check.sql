-- ==============================================================================
-- 0003_fix_run_health_verdict_check.sql - fix run.health_verdict CHECK
-- ==============================================================================
-- Description: 0001 copy-pasted finding.severity's 5-value CHECK
--              (CRITICAL/HIGH/MEDIUM/LOW/INFO) onto run.health_verdict, but
--              the report tool schema (analyst/src/schema.rs) has always
--              produced the run-level 3-value scale (healthy/degraded/
--              critical) — a different concept (overall run health vs.
--              per-finding severity). Every real analyst run hit the
--              constraint violation on write. Caught on Rome's first live
--              end-to-end run (2026-09-10).
-- Author: Matt Barham
-- Created: 2026-09-10
-- Modified: 2026-09-10
-- Version: 0.1.0
-- ==============================================================================

ALTER TABLE run DROP CONSTRAINT run_health_verdict_check;
ALTER TABLE run ADD CONSTRAINT run_health_verdict_check
    CHECK (health_verdict IN ('healthy', 'degraded', 'critical'));
