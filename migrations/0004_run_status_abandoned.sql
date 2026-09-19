-- ==============================================================================
-- 0004_run_status_abandoned.sql - add the `abandoned` run status
-- ==============================================================================
-- Description: A collector run whose analyst never processed it (analyst crash,
--              Postgres not yet up after a host boot, operator Ctrl-C) stays in
--              `running` forever. triage-analyst now claims the NEWEST such run
--              and marks every older one `abandoned`, so a single failed analyst
--              costs one report instead of permanently offsetting every later
--              cycle by one run. `failed` is reserved for the collector's own
--              failure path (collector/src/main.rs), so stranded-but-collected
--              runs need a status of their own to stay distinguishable in
--              history.
-- Author: Matt Barham
-- Created: 2026-09-19
-- Version: 0.1.0
-- ==============================================================================

ALTER TABLE run DROP CONSTRAINT run_status_check;

ALTER TABLE run ADD CONSTRAINT run_status_check
    CHECK (status = ANY (ARRAY[
        'pending',
        'running',
        'completed',
        'failed',
        'budget_exhausted',
        'abandoned'
    ]));
