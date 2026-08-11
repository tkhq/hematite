# Multi-stage build of the hematite binary, plus the test CA baked into the
# system trust store so upstream TLS verification (Part 07 §4) trusts the
# echo upstream's leaf.
FROM rust:1-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY spec ./spec
RUN cargo build --release --bin hematite

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/hematite /usr/local/bin/hematite
# The test CA (mounted at build context time) becomes a trusted system root
# so the dialer accepts the echo upstream's leaf.
COPY tests/acceptance/certs/ca.crt /usr/local/share/ca-certificates/hematite-test-ca.crt
RUN update-ca-certificates
COPY tests/acceptance/certs /etc/hematite/certs
COPY tests/acceptance/hematite.yaml /etc/hematite/hematite.yaml
COPY tests/acceptance/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY tests/acceptance/secrets /run/secrets
RUN chmod +x /usr/local/bin/entrypoint.sh
ENV OPENAI_API_KEY=sk-real-acceptance
ENV HEMATITE_MANAGEMENT_API_KEY=reload-token
EXPOSE 53/udp 80 443 8080 9092
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
