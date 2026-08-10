# Appendix B — Worked Example (informative, but Appendix A runs on it)

The complete config the acceptance test boots. Every mechanism in Parts 04–09
appears at least once — this file is where prose contradictions surface.

```yaml
# hematite.yaml — acceptance-test configuration
dns:
  listen: ":53"
  proxy_ip: "172.20.0.2"
  passthrough:
    - "*.internal.corp"
  records:
    - name: "internal.example.com"
      type: A
      value: "10.0.0.5"
    - name: "db.internal.corp"     # inside the passthrough zone on purpose:
      type: A                      # acceptance step 6 observes static > passthrough
      value: "10.0.0.9"

proxy:
  http_listen: ":80"
  https_listen: ":443"
  tunnel_listen: ":8080"
  max_request_body_bytes: 1048576
  # upstream_deny_cidrs omitted → default metadata+loopback set (Part 07 §2)

tls:
  ca_cert: "/etc/hematite/ca.crt"
  ca_key: "/etc/hematite/ca.key"

transforms:
  - name: allowlist
    config:
      domains:
        - "httpbin.org"
        - "*.anthropic.com"
      cidrs:
        - "172.20.0.0/24"

  - name: annotate
    config:
      annotations:
        - rules:
            - host: "httpbin.org"
          headers: ["x-request-id"]

  - name: body_capture
    config:
      max_request_body_bytes: 16384
      rules:
        - host: "httpbin.org"
          methods: ["POST"]
          paths: ["/anything*"]

  - name: secrets
    config:
      secrets:
        - source: { type: env, var: OPENAI_API_KEY }
          proxy_value: "proxy-openai-abc123"
          match_headers: ["Authorization"]
          require: true
          rules:
            - host: "httpbin.org"
              paths: ["/headers"]
        - source: { type: file, path: "/run/secrets/internal-token", ttl: "5m" }
          proxy_value: "proxy-internal-tok"
          match_headers: []          # scan all headers
          rules:
            - host: "httpbin.org"

  - name: header_allowlist
    config:
      headers:
        - "Authorization"
        - "Content-Type"
        - "User-Agent"
        - "Accept"
        - "Host"
        - "/^x-request-.*$/"
      rules:
        - host: "httpbin.org"

management:
  listen: "127.0.0.1:9092"
  api_key_env: "HEMATITE_MANAGEMENT_API_KEY"

log:
  level: "info"
```

## Walkthrough of acceptance step 3

`GET https://httpbin.org/headers` with `Authorization: Bearer
proxy-openai-abc123`, DNS-steered to the proxy:

1. DNS: `httpbin.org` matches no record/passthrough → `172.20.0.2`.
2. HTTPS listener mints (or LRU-hits) a leaf for SNI `httpbin.org`; SNI ==
   Host passes; path has no dot segments.
3. `allowlist`: `httpbin.org` matches domain 1 → Continue.
4. `annotate`: rule matches, no `x-request-id` present → Continue, no keys.
5. `body_capture`: method GET doesn't match → Continue.
6. `secrets` #1: rules match (`/headers`); Authorization contains the proxy
   value → swap; annotate `swapped`. #2: all-headers scan, token absent, not
   required → nothing.
7. `header_allowlist`: all present headers match entries → nothing stripped.
8. Guard: resolved IP is public → dial; hop-by-hop stripped; exact
   Content-Length (body untouched → original framing).
9. Response passes back through the (no-op) response path; audit record
   emitted — the one shown in Appendix C §4.
```
