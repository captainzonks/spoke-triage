#!/usr/bin/env bash
# ==============================================================================
# run_triage.sh - spoke-triage systemd ExecStart target
# ==============================================================================
# Description: Runs one triage cycle: collector (query/normalize/aggregate),
#              then analyst (classify/report, mails via spoke-mail-relay if
#              TRIAGE_MAIL_TO is set). Each binary's egress guard
#              (triage-collector-guard, triage-egress-guard) is started
#              implicitly by its `depends_on: condition: service_healthy`
#              and both are torn down unconditionally on exit (trap) so the
#              sidecars don't sit resolving/refreshing iptables between
#              timer firings.
# Author: Matt Barham
# Created: 2026-09-09
# Modified: 2026-09-27
# Version: 0.2.0
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

trap 'docker compose down triage-collector-guard triage-egress-guard --remove-orphans 2>/dev/null || true' EXIT

docker compose run --rm triage-collector
docker compose run --rm triage-analyst
