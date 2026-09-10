# ==============================================================================
# DOCKERFILE - triage-collector
# ==============================================================================
# Description: Multi-stage Rust build for the no-egress side of spoke-triage
#              (docs/spec.md §3.1). Builds the whole workspace (sqlx needs
#              the common/analyst/cli crates to resolve even though only the
#              collector binary is copied into the runtime stage) then keeps
#              only the collector binary + migrations in the final image.
# Author: Matt Barham
# Version: 0.1.0
# ==============================================================================
# Base Images: rust:1-slim (builder), alpine:latest (runtime)
# Target Architecture: x86_64-unknown-linux-musl (static binary)
# Security: non-root user, minimal Alpine runtime, no outbound network needed
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
RUN cargo build --release --target x86_64-unknown-linux-musl -p spoke-triage-collector

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

COPY --from=builder /usr/src/spoke-triage/target/x86_64-unknown-linux-musl/release/spoke-triage-collector /usr/local/bin/triage-collector
COPY --from=builder /usr/src/spoke-triage/migrations /app/migrations

RUN chmod +x /usr/local/bin/triage-collector && chown -R ${USERNAME}:${GROUPNAME} /app

USER ${USERNAME}
WORKDIR /app

LABEL maintainer="captainzonks"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${VCS_REF}"
LABEL org.opencontainers.image.version="${VERSION}"

CMD ["/usr/local/bin/triage-collector"]
