#!/usr/bin/env bash
# ==============================================================================
# run_triage.sh - spoke-triage systemd ExecStart target
# ==============================================================================
# Description: Runs one triage cycle: collector (query/normalize/aggregate),
#              then analyst (classify/report, mails via spoke-mail-relay if
#              TRIAGE_MAIL_TO is set). triage-egress-guard is started
#              implicitly by analyst's `depends_on: condition: service_healthy`
#              and torn down unconditionally on exit (trap) so the sidecar
#              doesn't sit resolving/refreshing iptables between timer firings.
# Author: Matt Barham
# Created: 2026-09-09
# Modified: 2026-09-10
# Version: 0.1.1
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

trap 'docker compose down triage-egress-guard --remove-orphans 2>/dev/null || true' EXIT

docker compose run --rm triage-collector
docker compose run --rm triage-analyst
