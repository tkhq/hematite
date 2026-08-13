# Load generator: vegeta for perf, curl/jq for conformance, python3 for the
# streaming and cold-start clients under /scripts, agentbench for the
# agent-traffic suite (the same binary also serves as the mock LLM upstream).
FROM golang:1.24-alpine AS build
RUN go install github.com/tsenart/vegeta/v12@v12.12.0

FROM rust:1-slim AS agentbuild
WORKDIR /src
COPY agentbench/Cargo.toml agentbench/Cargo.lock* ./
COPY agentbench/src ./src
RUN cargo build --release

FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl jq \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /go/bin/vegeta /usr/local/bin/vegeta
COPY --from=agentbuild /src/target/release/agentbench /usr/local/bin/agentbench
ENV SSL_CERT_FILE=/certs/ca.crt
CMD ["sleep", "infinity"]
