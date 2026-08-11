# Production image for the hematite binary. Mount your own config, CA, and
# secrets at runtime; nothing environment-specific is baked in.
#
#   docker run --rm \
#     -v $PWD/hematite.yaml:/etc/hematite/hematite.yaml:ro \
#     -v $PWD/ca:/etc/hematite/certs:ro \
#     ghcr.io/tkhq/hematite:latest
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
# HTTP, HTTPS (MITM), tunnel, management, DNS.
EXPOSE 80 443 8080 9092 53/udp 53/tcp
ENTRYPOINT ["hematite", "-config", "/etc/hematite/hematite.yaml"]
