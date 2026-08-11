# The acceptance client, with curl + dig baked in so it needs no network
# access at runtime (its DNS is pointed at the proxy, which would intercept
# package mirrors).
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl dnsutils ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/bin/bash", "/run.sh"]
