# ==============================================================================
# DOCKERFILE - triage-analyst
# ==============================================================================
# Description: Multi-stage Rust build for the only-egress side of
#              spoke-triage (docs/spec.md §3.2). Builds the whole workspace
#              then keeps only the analyst binary in the final image.
# Author: Matt Barham
# Version: 0.1.0
# ==============================================================================
# Base Images: rust:1-slim (builder), alpine:latest (runtime)
# Target Architecture: x86_64-unknown-linux-musl (static binary)
# Security: non-root user, minimal Alpine runtime, outbound restricted to
#           api.anthropic.com at the compose/iptables layer (spec §3.2) —
#           this image itself has no special network privilege.
# ==============================================================================

#=============================================================================
# BUILD STAGE
#=============================================================================

FROM rust:1-slim AS builder

RUN apt update -qq && apt install -y -qq --no-install-recommends musl-tools pkg-config

RUN rustup set profile minimal && rustup target add x86_64-unknown-linux-musl

WORKDIR /usr/src/spoke-triage
COPY ./Cargo.toml ./Cargo.lock ./
COPY ./common ./common/
COPY ./collector ./collector/
COPY ./analyst ./analyst/
COPY ./cli ./cli/
COPY ./migrations ./migrations/

ENV RUSTFLAGS='-C link-arg=-s'
RUN cargo build --release --target x86_64-unknown-linux-musl -p spoke-triage-analyst -p spoke-triage-cli

#=============================================================================
# RUNTIME STAGE
#=============================================================================

FROM alpine:latest

RUN apk add --no-cache ca-certificates

ARG BUILD_DATE
ARG VCS_REF
ARG VERSION
ARG USER_ID=1000
ARG GROUP_ID=968
ARG USERNAME=triage
ARG GROUPNAME=triage

RUN addgroup -g ${GROUP_ID} ${GROUPNAME} \
    && adduser -D -u ${USER_ID} -G ${GROUPNAME} -s /bin/sh ${USERNAME}

COPY --from=builder /usr/src/spoke-triage/target/x86_64-unknown-linux-musl/release/spoke-triage-analyst /usr/local/bin/triage-analyst
COPY --from=builder /usr/src/spoke-triage/target/x86_64-unknown-linux-musl/release/triage-cli /usr/local/bin/triage-cli

RUN mkdir -p /app && chown -R ${USERNAME}:${GROUPNAME} /app \
    && chmod +x /usr/local/bin/triage-analyst /usr/local/bin/triage-cli

USER ${USERNAME}
WORKDIR /app

LABEL maintainer="captainzonks"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${VCS_REF}"
LABEL org.opencontainers.image.version="${VERSION}"

CMD ["/usr/local/bin/triage-analyst"]
