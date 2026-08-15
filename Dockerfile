# syntax=docker/dockerfile:1
# ============================================================================
# MCPG — Model Context Protocol Gateway
# ----------------------------------------------------------------------------
# Self-contained image built from this crate's source alone, on public base
# images. Two stages: a Rust builder compiles the `mcpg` gateway; a slim
# Debian runtime carries just the binary and runs it as a non-root user.
#
#   docker build -t mcpg:local .
#   docker run --rm -p 8787:8787 -v "$PWD/config.yaml:/etc/mcpg/config.yaml" mcpg:local
# ============================================================================

FROM rust:1-bookworm AS build

# aws-lc-rs (rustls crypto provider) builds its C sources at compile time and
# needs cmake + clang/bindgen; the rest are standard native-build tooling.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        cmake clang libclang-dev perl pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
# An existing Cargo.lock (the release pipeline stages the resolved one into
# the build context) pins the graph; without one the build resolves fresh.
RUN cargo build --release --bin mcpg

# ----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.title="mcpg" \
      org.opencontainers.image.description="Model Context Protocol Gateway" \
      org.opencontainers.image.licenses="Apache-2.0"

# ca-certificates for outbound TLS; tini for PID-1 signal handling.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 mcpg \
    && mkdir -p /etc/mcpg /var/lib/mcpg \
    && chown -R mcpg:mcpg /var/lib/mcpg

COPY --from=build /src/target/release/mcpg /usr/local/bin/mcpg

USER mcpg
WORKDIR /home/mcpg

ENV MCPG_CONFIG=/etc/mcpg/config.yaml \
    MCPG_GATEWAY__SERVER__BIND_ADDRESS=0.0.0.0:8787 \
    MCPG_OBSERVABILITY__LOGS__LEVEL=info \
    RUST_LOG=info

EXPOSE 8787

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/mcpg", "--health-check"]

# tini wraps the binary so an `args`-only override appends flags to `mcpg`
# rather than replacing the command.
ENTRYPOINT ["tini", "--", "mcpg"]
