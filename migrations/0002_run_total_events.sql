-- ==============================================================================
-- 0002_run_total_events.sql - add run.total_events
-- ==============================================================================
-- Description: docs/spec.md §5 lists total_events as a top-level report
--              field alongside summary and health verdict, but 0001 didn't
--              give it a column — caught when triage-analyst's report parser
--              had nowhere to persist it.
-- Author: Matt Barham
-- Created: 2026-09-09
-- Modified: 2026-09-09
-- Version: 0.1.0
-- ==============================================================================

ALTER TABLE run ADD COLUMN total_events BIGINT CHECK (total_events >= 0);

COMMENT ON COLUMN run.total_events IS 'Sum of counts across templates considered in this run, from the model report (spec §5).';

GRANT SELECT, INSERT, UPDATE ON run TO triage_app;
