# Squid with OpenSSL (ssl-bump) — the Ubuntu 'squid' package is built
# without TLS; 'squid-openssl' carries the ssl_crtd helper we need.
FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends squid-openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
# Initialize the dynamic-cert db at start, then run in the foreground.
CMD ["sh", "-c", "rm -rf /var/spool/squid/ssl_db && /usr/lib/squid/security_file_certgen -c -s /var/spool/squid/ssl_db -M 16MB && exec squid -N -f /etc/squid/squid.conf"]
