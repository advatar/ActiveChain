FROM rust:1.97.1-bookworm AS builder

WORKDIR /src
COPY . .
RUN cargo build --locked --release -p activechain-payment-verifier-service

FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --uid 10001 --home /nonexistent --shell /usr/sbin/nologin --no-create-home verifier
COPY --from=builder /src/target/release/activechain-payment-verifier-service /usr/local/bin/activechain-payment-verifier-service
USER verifier
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=6 CMD curl -fsS http://127.0.0.1:8080/healthz >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/activechain-payment-verifier-service"]
