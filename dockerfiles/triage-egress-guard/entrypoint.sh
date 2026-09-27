#!/bin/sh
# ==============================================================================
# entrypoint.sh - triage-egress-guard
# ==============================================================================
# Description: Fail-closed outbound allowlist for a network namespace
#              shared with one triage container (ADR-015, ADR-028). Two
#              profiles, chosen by TRIAGE_EGRESS_PROFILE:
#                analyst   (default) Postgres, api.anthropic.com:443 and the
#                          mail relay (docs/spec.md §3.2)
#                collector Postgres and Loki only: no internet at all
#                          (docs/spec.md §3.1)
#              Resolves the allowed hosts, then restricts OUTPUT to just
#              those destinations (+ DNS + loopback + established). IPs can
#              change, so the allowlist is rebuilt on a timer rather than
#              resolved once. Any resolution failure — at startup or on
#              refresh — keeps the previous rule set rather than opening up:
#              policy DROP is set before the chain is ever flushed, so there
#              is no window where OUTPUT defaults to ACCEPT.
# Author: Matt Barham
# Created: 2026-09-09
# Modified: 2026-09-27
# Version: 0.2.0
# ==============================================================================

set -eu

PROFILE="${TRIAGE_EGRESS_PROFILE:-analyst}"
REFRESH_SECONDS="${TRIAGE_EGRESS_REFRESH_SECONDS:-300}"
ANTHROPIC_HOST="${TRIAGE_EGRESS_ANTHROPIC_HOST:-api.anthropic.com}"
POSTGRES_HOST="${POSTGRES_HOST:?POSTGRES_HOST must be set}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
MAIL_RELAY_HOST="${TRIAGE_MAIL_RELAY_HOST:-mail-relay}"
MAIL_RELAY_PORT="${TRIAGE_MAIL_RELAY_PORT:-8000}"
READY_MARKER=/tmp/rules-applied

case "$PROFILE" in
    analyst|collector) ;;
    *) echo "triage-egress-guard: unknown TRIAGE_EGRESS_PROFILE '$PROFILE' (analyst|collector)" >&2; exit 1 ;;
esac

# The collector profile allows exactly the Loki instance the collector
# queries, taken from the same TRIAGE_LOKI_BASE_URL the collector uses so
# the two can't drift. Only http(s)://host[:port][/path] is accepted.
if [ "$PROFILE" = collector ]; then
    LOKI_URL="${TRIAGE_LOKI_BASE_URL:?TRIAGE_LOKI_BASE_URL must be set for the collector profile}"
    case "$LOKI_URL" in
        http://*) loki_default_port=80 ;;
        https://*) loki_default_port=443 ;;
        *) echo "triage-egress-guard: TRIAGE_LOKI_BASE_URL must start with http:// or https:// (got '$LOKI_URL')" >&2; exit 1 ;;
    esac
    loki_authority=$(printf '%s' "$LOKI_URL" | sed -E 's#^[a-z]+://##; s#/.*$##')
    LOKI_HOST=$(printf '%s' "$loki_authority" | sed -E 's#:.*$##')
    case "$loki_authority" in
        *:*) LOKI_PORT=$(printf '%s' "$loki_authority" | sed -E 's#^.*:##') ;;
        *) LOKI_PORT=$loki_default_port ;;
    esac
    case "$LOKI_PORT" in
        ''|*[!0-9]*) echo "triage-egress-guard: bad Loki port in TRIAGE_LOKI_BASE_URL (got '$LOKI_PORT')" >&2; exit 1 ;;
    esac
    [ -n "$LOKI_HOST" ] || { echo "triage-egress-guard: no host in TRIAGE_LOKI_BASE_URL" >&2; exit 1; }
fi

resolve_a_records() {
    dig +short A "$1" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u
}

apply_rules() {
    postgres_ips=$(resolve_a_records "$POSTGRES_HOST") || postgres_ips=""
    if [ "$PROFILE" = collector ]; then
        loki_ips=$(resolve_a_records "$LOKI_HOST") || loki_ips=""
        if [ -z "$loki_ips" ] || [ -z "$postgres_ips" ]; then
            echo "triage-egress-guard[collector]: resolution failed (loki=[$loki_ips] postgres=[$postgres_ips]), keeping existing rules" >&2
            return 1
        fi
    else
        anthropic_ips=$(resolve_a_records "$ANTHROPIC_HOST") || anthropic_ips=""
        if [ -z "$anthropic_ips" ] || [ -z "$postgres_ips" ]; then
            echo "triage-egress-guard: resolution failed (anthropic=[$anthropic_ips] postgres=[$postgres_ips]), keeping existing rules" >&2
            return 1
        fi
    fi

    # Policy DROP first, then flush: removes the old allowlist without ever
    # exposing a default-ACCEPT window, even on refresh.
    iptables -P OUTPUT DROP
    iptables -F OUTPUT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

    for ip in $postgres_ips; do
        iptables -A OUTPUT -p tcp -d "$ip" --dport "$POSTGRES_PORT" -j ACCEPT
    done

    if [ "$PROFILE" = collector ]; then
        for ip in $loki_ips; do
            iptables -A OUTPUT -p tcp -d "$ip" --dport "$LOKI_PORT" -j ACCEPT
        done
        touch "$READY_MARKER"
        echo "triage-egress-guard[collector]: rules applied - loki=[$loki_ips]:$LOKI_PORT postgres=[$postgres_ips]"
        return 0
    fi

    for ip in $anthropic_ips; do
        iptables -A OUTPUT -p tcp -d "$ip" --dport 443 -j ACCEPT
    done

    # Mail relay is best-effort: it's an internal Spoke destination (never
    # the public internet), and losing report delivery shouldn't block the
    # postgres+anthropic rules that classification/persistence depend on.
    mail_relay_ips=$(resolve_a_records "$MAIL_RELAY_HOST") || mail_relay_ips=""
    if [ -n "$mail_relay_ips" ]; then
        for ip in $mail_relay_ips; do
            iptables -A OUTPUT -p tcp -d "$ip" --dport "$MAIL_RELAY_PORT" -j ACCEPT
        done
    else
        echo "triage-egress-guard: mail relay host $MAIL_RELAY_HOST did not resolve, report email will fail this cycle" >&2
    fi

    touch "$READY_MARKER"
    echo "triage-egress-guard: rules applied - anthropic=[$anthropic_ips] postgres=[$postgres_ips] mail_relay=[$mail_relay_ips]"
}

# Set the fail-closed policy immediately, before the first resolution attempt
# — if this script crashes before apply_rules ever succeeds, OUTPUT is still
# DROP, not the container's default ACCEPT. But DROP with an empty chain
# also blocks the loopback DNS query (127.0.0.11, Docker's embedded
# resolver) that apply_rules itself needs in order to resolve anything —
# bootstrap loopback + DNS ACCEPT rules before the first resolution attempt,
# not after. apply_rules() re-adds them on every flush, so this bootstrap
# only matters for the window before apply_rules first succeeds.
iptables -P OUTPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

until apply_rules; do
    echo "triage-egress-guard: initial resolution failed, retrying in 5s" >&2
    sleep 5
done

while true; do
    sleep "$REFRESH_SECONDS"
    apply_rules || echo "triage-egress-guard: refresh failed, previous rules remain in effect" >&2
done
