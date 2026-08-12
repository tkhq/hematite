# Load generator: vegeta for perf, curl/jq for conformance, python3 for the
# streaming and cold-start clients under /scripts.
FROM golang:1.24-alpine AS build
RUN go install github.com/tsenart/vegeta/v12@v12.12.0

FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl jq \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /go/bin/vegeta /usr/local/bin/vegeta
ENV SSL_CERT_FILE=/certs/ca.crt
CMD ["sleep", "infinity"]
