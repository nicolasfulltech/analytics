FROM rust:1.94-slim-bookworm AS builder

WORKDIR /build
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev cmake \
    && rm -rf /var/lib/apt/lists/*

# Cache deps. Cargo.toml declares bench targets, so their files must exist
# at manifest-parse time even when we're only building the main binary.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src benches \
    && echo "fn main() {}" > src/main.rs \
    && echo "fn main() {}" > benches/ingest.rs \
    && echo "fn main() {}" > benches/queries.rs \
    && cargo build --release --bin simple-analytics \
    && rm -rf src benches

COPY . .
RUN cargo build --release --bin simple-analytics \
    && strip target/release/simple-analytics

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -u 10001 -r -s /usr/sbin/nologin -d /app analytics \
    && mkdir -p /app/data \
    && chown -R analytics:analytics /app

WORKDIR /app
COPY --from=builder /build/target/release/simple-analytics /usr/local/bin/simple-analytics

USER analytics
ENV ANALYTICS_DATABASE__PATH=/app/data/analytics.db \
    ANALYTICS_SERVER__BIND=0.0.0.0:8080 \
    RUST_LOG=info

EXPOSE 8080
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://localhost:8080/readyz || exit 1

CMD ["simple-analytics"]
