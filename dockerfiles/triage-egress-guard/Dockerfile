# ==============================================================================
# DOCKERFILE - triage-egress-guard
# ==============================================================================
# Description: Sidecar that owns the network namespace shared with
#              triage-analyst (network_mode: service:triage-egress-guard) and
#              restricts its OUTPUT to api.anthropic.com + POSTGRES_HOST
#              (docs/spec.md §3.2, ADR-013). No compiled app — iptables +
#              dig + a small POSIX shell loop.
# Author: Matt Barham
# Version: 0.1.0
# ==============================================================================
# Base Image: alpine:latest
# Security: runs as root (NET_ADMIN + iptables require it), cap_drop ALL
#           except NET_ADMIN/NET_RAW at the compose layer — this is the only
#           container in spoke-triage that needs elevated network caps.
# ==============================================================================

FROM alpine:latest

RUN apk add --no-cache iptables bind-tools

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD test -f /tmp/rules-applied || exit 1

LABEL maintainer="captainzonks"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${VCS_REF}"
LABEL org.opencontainers.image.version="${VERSION}"

ENTRYPOINT ["/entrypoint.sh"]
