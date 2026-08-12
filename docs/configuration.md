# hematite configuration reference

hematite is configured by a single YAML file passed with `-config`:

```sh
hematite -config /etc/hematite/hematite.yaml
```

The file is validated at boot: any error (an unknown key, a bad glob, a
missing required field) stops startup immediately, before any request is
served. This reference describes every key. For the normative definitions see
[`spec/09-config.md`](../spec/09-config.md) and the per-feature parts.

- [A complete example](#a-complete-example)
- [Load order and environment overrides](#load-order-and-environment-overrides)
- [Conformance levels: which listeners run](#conformance-levels-which-listeners-run)
- [`proxy`](#proxy) · [`tls`](#tls) · [`dns`](#dns) · [`management`](#management) · [`log`](#log) · [`observability`](#observability)
- [`transforms`](#transforms): the policy pipeline
- [Rules and matching](#rules-and-matching)
- [Reloading](#reloading)

---

## A complete example

```yaml
# DNS interception: answer every lookup with the proxy's own IP so traffic
# arrives at the listeners without the client cooperating.
dns:
  enabled: true
  listen: ":53"
  proxy_ip: "172.20.0.2"
  upstream_resolver: "1.1.1.1:53"
  passthrough:
    - "*.internal.corp"          # forwarded upstream (bypasses interception)
  records:
    - name: "db.internal.corp"   # a static answer (beats passthrough)
      type: A
      value: "10.0.0.9"

proxy:
  http_listen: ":80"
  https_listen: ":443"           # requires the `tls` block below
  tunnel_listen: ":8080"         # CONNECT / SOCKS5
  max_request_body_bytes: 1048576
  # upstream_deny_cidrs omitted -> default metadata + loopback deny set

tls:
  ca_cert: "/etc/hematite/certs/ca.crt"
  ca_key: "/etc/hematite/certs/ca.key"

transforms:
  - name: allowlist              # default-deny destination filter (required)
    config:
      domains: ["api.openai.com", "*.anthropic.com"]
      cidrs: ["10.0.0.0/8"]

  - name: annotate               # copy request headers into the audit log
    config:
      annotations:
        - rules: [{ host: "api.openai.com" }]
          headers: ["x-request-id"]

  - name: body_capture           # record request bodies for audit
    config:
      max_request_body_bytes: 16384
      rules: [{ host: "api.anthropic.com", methods: ["POST"], paths: ["/v1/messages"] }]

  - name: secrets                # swap proxy tokens for real credentials
    config:
      secrets:
        - source: { type: env, var: OPENAI_API_KEY }
          proxy_value: "proxy-openai-abc123"
          match_headers: ["Authorization"]
          require: true
          rules: [{ host: "api.openai.com" }]

  - name: header_allowlist       # drop request headers not on the list
    config:
      headers: ["Authorization", "Content-Type", "Accept", "User-Agent", "/^x-request-.*$/"]
      rules: [{ host: "api.openai.com" }]

management:
  listen: "127.0.0.1:9092"
  api_key_env: "HEMATITE_MANAGEMENT_API_KEY"

log:
  level: "info"

observability:
  metrics:
    enabled: true           # serve GET /metrics on the management port (default true)
  log:
    format: json            # json | text; default json. Operational logs only.
  otlp:
    enabled: false          # OTLP trace export; default off
    endpoint: "http://otel-collector:4318"  # required when enabled
    sample_ratio: 1.0       # head sampling probability, 0.0–1.0
    service_name: "hematite"
```

The recommended transform order is `allowlist`, `annotate`, `body_capture`,
`secrets`, `header_allowlist`; hematite never reorders the pipeline, and it
warns if `allowlist` is not first or if `body_capture` follows a
body-rewriting `secrets` entry.

---

## Load order and environment overrides

The config is resolved in four steps:

1. Parse the YAML file.
2. Apply `HEMATITE_`-prefixed environment overrides.
3. Apply defaults.
4. Validate.

Any scalar key can be overridden from the environment. The variable name is
the dotted config path, uppercased and joined with `_`, prefixed with
`HEMATITE_`:

| Config key | Environment variable |
|---|---|
| `proxy.http_listen` | `HEMATITE_PROXY_HTTP_LISTEN` |
| `dns.proxy_ip` | `HEMATITE_DNS_PROXY_IP` |
| `tls.ca_cert` | `HEMATITE_TLS_CA_CERT` |
| `management.listen` | `HEMATITE_MANAGEMENT_LISTEN` |
| `observability.metrics.enabled` | `HEMATITE_OBSERVABILITY_METRICS_ENABLED` |
| `observability.log.format` | `HEMATITE_OBSERVABILITY_LOG_FORMAT` |
| `observability.otlp.enabled` | `HEMATITE_OBSERVABILITY_OTLP_ENABLED` |
| `observability.otlp.endpoint` | `HEMATITE_OBSERVABILITY_OTLP_ENDPOINT` |
| `observability.otlp.sample_ratio` | `HEMATITE_OBSERVABILITY_OTLP_SAMPLE_RATIO` |
| `observability.otlp.service_name` | `HEMATITE_OBSERVABILITY_OTLP_SERVICE_NAME` |

Overridable keys: everything under `dns`, `proxy`, `tls`, `management`,
`log`, and `observability` except the list/structured fields (`dns.passthrough`,
`dns.records`, `proxy.upstream_deny_cidrs`, and the `transforms` list). Secret
**values** are never set in config or overrides; only the *name* of the env
var or the file path is configured (see [`secrets`](#secrets)).

---

## Conformance levels: which listeners run

hematite is layered into conformance levels (spec Part 00 §4). A listener
runs only at the level that defines it, and section defaults apply only when
that section is present:

| Level | Serves |
|---|---|
| **L1** | the plain-HTTP listener, the guard, the audit log, config + reload |
| **L2** | adds the HTTPS (TLS MITM) listener, the tunnel listener, and the DNS server |
| **L3** | adds the `secrets` transform |

Practically:

- A minimal config with just an `allowlist` transform is valid and serves
  plain HTTP only.
- `https_listen` and `tunnel_listen` are **off unless set**. Setting
  `https_listen` requires a `tls` block.
- An absent `dns:` block means no DNS server. Within a present block,
  `dns.enabled` defaults to `true`.
- Feature-specific validation (`dns.proxy_ip`, `tls.ca_cert`/`ca_key`) is
  enforced only when that feature is enabled.

---

## `proxy`

Listener addresses and upstream behavior.

| Key | Type | Default | Notes |
|---|---|---|---|
| `http_listen` | address | `:80` | plain-HTTP listener |
| `https_listen` | address | *unset* | TLS MITM listener; requires `tls` |
| `tunnel_listen` | address | *unset* | CONNECT / SOCKS5 listener |
| `max_request_body_bytes` | integer | `1048576` (1 MiB) | request-body buffer cap |
| `max_response_body_bytes` | integer | `0` (uncapped) | response-body buffer cap |
| `upstream_response_header_timeout` | duration | `30s` | time-to-first-byte from upstream → 502 |
| `upstream_deny_cidrs` | list | metadata + loopback | the guard (see below) |
| `http_proxy` / `https_proxy` / `no_proxy` | string | none | **accepted but not yet wired** (egress chaining is planned) |

Addresses are `host:port`; a leading `:` binds all interfaces (`:80` →
`0.0.0.0:80`). Durations are bare seconds or `<n>ms`/`<n>s`/`<n>m`.

**The guard (`upstream_deny_cidrs`).** After a request passes policy,
hematite resolves the destination and checks the *actual* IP it is about to
dial against this deny list, closing SSRF and DNS-rebinding (an allowlisted
name whose record points at cloud metadata still fails at the socket).

- **Absent** → the default deny set: `169.254.169.254/32`, `fd00:ec2::254/128`,
  `fd20:ce::254/128` (cloud metadata), `127.0.0.0/8`, `::1/128` (loopback).
  RFC 1918 ranges are deliberately *not* denied by default.
- **Explicitly empty** (`upstream_deny_cidrs: []`) → the guard is disabled.
  This is distinct from absent.
- A denied dial returns 502 and audits as a policy denial (`rejected_by:
  "guard"`). The audit category is a denial; transport failures use their
  own category.

---

## `tls`

Required when `https_listen` or `tunnel_listen` is set. hematite mints a
short-lived leaf certificate per destination hostname, signed by this CA, so
clients that trust the CA accept the MITM.

| Key | Type | Default | Notes |
|---|---|---|---|
| `ca_cert` | path | required | PEM CA certificate (`CA:TRUE`) |
| `ca_key` | path | required | PEM CA private key (PKCS#8) |
| `cert_cache_size` | integer | `1000` | per-hostname leaf LRU cache |
| `leaf_cert_expiry_hours` | integer | `72` | minted-leaf lifetime |

The CA certificate must be installed in the **workload's** trust store (so
it accepts the minted leaves) and, if the proxy dials TLS upstreams that use
a private CA, in the **proxy's** system trust store (upstream connections are
verified against the system roots). Leaves are ECDSA P-256, `serverAuth`
only, one SAN = the target.

---

## `dns`

The interception DNS server (spec Part 06). Point the workload's resolver at
this address and every lookup is answered with `proxy_ip`, so traffic lands
on the listeners.

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `true` | within a present `dns:` block |
| `listen` | address | `:53` | UDP and TCP are both served |
| `proxy_ip` | IPv4 | required | **required** when enabled; the intercept answer |
| `upstream_resolver` | address | `1.1.1.1:53` | where passthrough queries go |
| `passthrough` | list of globs | `[]` | names forwarded upstream, bypassing interception |
| `records` | list | `[]` | static `A`/`CNAME` answers |

Resolution precedence for each query: **static records** (exact name) >
**passthrough** (glob match → forward to `upstream_resolver`) > **intercept**
(answer `A` → `proxy_ip`). `AAAA` and other types for an intercepted name
return an empty `NOERROR` so dual-stack clients fall back to the A record.

`upstream_resolver` defaults to a concrete public resolver (`1.1.1.1:53`).
Inside an intercepted network the host's OS resolver may point back at
hematite and loop, so a fixed external resolver is the safe default.

Static records:

```yaml
records:
  - { name: "db.internal.corp", type: A, value: "10.0.0.9" }
  - { name: "alias.example.com", type: CNAME, value: "real.example.com" }
```

A `CNAME` is returned as-is; the server does not chase the target (the client
re-queries the canonical name).

> DNS steering is cooperative: a workload can hardcode IPs or use DoH to
> bypass it. Making the boundary unavoidable (nftables/TPROXY) is a
> deployment responsibility, outside hematite's scope.

---

## `management`

An optional loopback control endpoint for reloads.

| Key | Type | Default | Notes |
|---|---|---|---|
| `listen` | address | *unset* (disabled) | SHOULD bind loopback |
| `api_key_env` | string | `HEMATITE_MANAGEMENT_API_KEY` | env var holding the bearer token |

When `listen` is set, the named env var must hold a non-empty token at boot.
See [Reloading](#reloading).

---

## `log`

| Key | Type | Default | Notes |
|---|---|---|---|
| `level` | string | `info` | **accepted but does not yet change output verbosity** |

Audit records (one JSON line per request) are always emitted on stderr
regardless of this setting.

---

## `observability`

Production telemetry: a Prometheus metrics endpoint, structured operational
logs, and optional OTLP trace export.

### `observability.metrics`

| Key | Type | Default | Env override |
|---|---|---|---|
| `enabled` | bool | `true` | `HEMATITE_OBSERVABILITY_METRICS_ENABLED` |

When `enabled` is `true` (the default), `GET /metrics` on the management port
serves a Prometheus text exposition. When `false`, `GET /metrics` returns 404.
Requires `management.listen` to be set; there is no standalone metrics port.

Metric counters survive a config reload; the registry is preserved across the
hot swap.

**Metrics reference:**

| Metric | Type | Labels |
|---|---|---|
| `hematite_build_info` | gauge (always 1) | `version` |
| `hematite_requests_total` | counter | `mode` (`http`/`https`/`tunnel`), `action` (`allow`/`reject`/`stub`/`error`/`client-cancel`), `rejected_by` (transform name, `"listener"`, `"guard"`, or `""`) |
| `hematite_request_duration_seconds` | histogram | `mode`, `action`; fixed buckets 0.005–30 s |
| `hematite_upstream_dials_total` | counter | `result` (`ok`/`guard-denied`/`dns-error`/`connect-error`/`tls-error`) |
| `hematite_dns_queries_total` | counter | `outcome` (`intercept`/`static`/`passthrough`/`error`) |
| `hematite_tls_leaf_cache_events_total` | counter | `event` (`hit`/`miss`) |
| `hematite_secrets_swaps_total` | counter | `result` (`swapped`/`missing-required`/`source-error`). No secret-name label. |
| `hematite_config_reloads_total` | counter | `result` (`ok`/`error`) |

All label values are drawn from closed enums or a fixed transform list, so
cardinality is bounded. Per-host labels are deliberately absent: they would be
unbounded in cardinality and would leak allowlist traffic patterns through an
unauthenticated endpoint. Per-host data lives in the audit stream (Part 08).

### `observability.log`

| Key | Type | Default | Env override |
|---|---|---|---|
| `format` | `json` or `text` | `json` | `HEMATITE_OBSERVABILITY_LOG_FORMAT` |

Operational log events (startup, bind, reload, shutdown, warnings) are written
to **stdout** as newline-delimited JSON objects. Each line has `level`,
`timestamp`, `target`, and `fields.message` at minimum.

Set `format: text` for a compact single-line format in local development.

Audit records are always on **stderr**, unchanged (Part 08). The two streams
are never interleaved.

### `observability.otlp`

| Key | Type | Default | Env override |
|---|---|---|---|
| `enabled` | bool | `false` | `HEMATITE_OBSERVABILITY_OTLP_ENABLED` |
| `endpoint` | URL | required when enabled | `HEMATITE_OBSERVABILITY_OTLP_ENDPOINT` |
| `sample_ratio` | float | `1.0` | `HEMATITE_OBSERVABILITY_OTLP_SAMPLE_RATIO` |
| `service_name` | string | `hematite` | `HEMATITE_OBSERVABILITY_OTLP_SERVICE_NAME` |

OTLP trace export is off by default. When enabled, `endpoint` is required:
boot will fail without it. `endpoint` is the OTLP/HTTP base URL (e.g.
`http://otel-collector:4318`); the exporter appends `/v1/traces`.

`sample_ratio` is a head-sampling probability in `[0.0, 1.0]`. `1.0` samples
every request; `0.0` samples nothing. Values outside this range fail at boot.

hematite always creates fresh root spans. It never reads an incoming
`traceparent` header and never injects one into upstream requests. This is by
design: the client is untrusted, and forged trace context must not bias
operator telemetry.

Export uses OTLP/HTTP-protobuf over hyper; no gRPC. Export failures are logged
(throttled) and do not affect request handling. Shutdown flushes up to 5
seconds; spans not delivered within that window may be lost.

---

## `transforms`

The policy pipeline: an ordered list of transforms, each `{ name, config }`.
Every request runs through them in file order; a transform can rewrite the
request, reject it, or serve a canned response. Order is significant and
hematite never reorders it. v1 defines exactly five transforms; naming any
other fails validation.

An `allowlist` transform is **required**. A config without one fails to
load, because default-deny is structural.

### `allowlist`

Default-deny destination filter. Continues if the host matches; otherwise
rejects with 403.

```yaml
- name: allowlist
  config:
    domains: ["api.openai.com", "*.anthropic.com"]  # domain globs
    cidrs: ["10.0.0.0/8"]                            # for IP-literal hosts
    warn: false                                      # optional
```

At least one of `domains`/`cidrs` must be non-empty. With `warn: true`, a
would-be rejection is allowed through and annotated instead (audit only),
useful for staging a new policy.

### `annotate`

Copies named request headers into the audit record (never rejects). Use it
to enrich records with request IDs, trace headers, etc.

```yaml
- name: annotate
  config:
    annotations:
      - rules: [{ host: "api.openai.com", methods: ["POST"], paths: ["/v1/*"] }]
        headers: ["x-request-id"]      # literal names only
```

Captured values land in the log in plain text. Never annotate headers
holding real secrets (proxy tokens are fine). A repeated header records its
first occurrence.

### `body_capture`

Records the request body into the audit record's `body_capture` group (never
rejects; response bodies are not captured).

```yaml
- name: body_capture
  config:
    max_request_body_bytes: 16384      # capture cap, independent of the global cap
    rules: [{ host: "api.anthropic.com", methods: ["POST"], paths: ["/v1/messages"] }]
```

`rules` is **required and non-empty**: capture is opt-in per destination,
never global.

### `secrets` (L3)

Boundary credential custody: the workload sends a placeholder proxy token;
hematite swaps in the real secret at egress. The real value can never appear
in any log, audit record, or error.

```yaml
- name: secrets
  config:
    secrets:
      - source: { type: env, var: OPENAI_API_KEY }   # or type: file
        proxy_value: "proxy-openai-abc123"
        match_headers: ["Authorization"]  # [] or absent = all headers
        match_query: false
        match_path: false
        match_body: false
        require: false
        rules: [{ host: "api.openai.com" }]
```

Each secret replaces every occurrence of `proxy_value` in the opted-in
locations with the resolved secret:

- **`match_headers`**: a list of header-name patterns, or `[]`/absent for
  all headers. A valid `Authorization: Basic <b64>` value is decoded,
  swapped, and re-encoded.
- **`match_query`** / **`match_path`**: off by default (they leak into
  access logs). When `match_path` is set, `proxy_value` must be RFC 3986
  unreserved-only.
- **`match_body`**: byte-level replace in the buffered body.
- **`require: true`**: if the rules match but no proxy token was present (or
  the source can't be resolved), the request is rejected. This stops a
  compromised workload from bringing its own credentials.

**Sources:**

```yaml
source: { type: env, var: OPENAI_API_KEY, json_key: null }
source: { type: file, path: /run/secrets/tok, ttl: "5m", failure_ttl: "1m", json_key: null }
```

- `env` reads the proxy's environment (once).
- `file` reads a file; with `ttl` set it refreshes on expiry. `failure_ttl`
  (default `1m`) caches failures; on a refresh failure after a prior success
  the stale value is served and a retry is scheduled.
- `json_key` (optional) parses the resolved value as a JSON object and takes
  the named top-level string field.

### `header_allowlist`

Default-deny **request-header** filter: any request header whose name is not
on the list is removed before the request goes upstream (never rejects).

```yaml
- name: header_allowlist
  config:
    headers: ["Authorization", "Content-Type", "Accept", "/^x-trace-.*$/"]
    rules: [{ host: "api.openai.com" }]   # optional; absent = all requests
```

Place it after `secrets` (so injected credentials survive) and after
`annotate` (so annotation sees the original headers).

---

## Rules and matching

Many transforms (and the DNS server) select requests with the same **rule**
shape:

```yaml
- host: "*.example.com"        # domain glob OR CIDR (required)
  methods: ["POST", "PUT"]     # optional; absent = any method
  paths: ["/v1/*"]             # optional; absent = any path
```

A rule matches when the host clause matches **and** (if present) the method
matches **and** (if present) a path pattern matches. A rule *list* matches if
any rule matches. A present-but-empty `rules: []` is a validation error;
"match everything" is expressed by omitting the key where a transform allows
it (e.g. `header_allowlist`).

- **Domain globs**: case-insensitive. `*` is only valid as the leading
  label: `*.example.com` matches `example.com` and any subdomain depth. A
  pattern with no `*` matches exactly.
- **CIDRs**: match only IP-literal hosts inside the prefix (never
  hostnames). A prefix length is required: write `10.0.0.0/8`. A bare host
  address like `10.0.0.1` is rejected.
- **Path globs**: case-sensitive, matched against the raw (percent-encoded)
  path. `*` matches any run of characters including `/`. No `**`, `?`, or
  character classes.
- **Header-name patterns**: a literal name (case-insensitive), or a
  slash-delimited regex (`/^x-.*-key$/`, RE2-class, case-insensitive).

---

## Reloading

With `management.listen` set, config can be swapped without dropping traffic:

```sh
curl -XPOST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9092/v1/reload
```

Reload re-reads the config file, builds a completely new pipeline plus DNS
and TLS state, and swaps it atomically. In-flight requests finish on the old
pipeline.

- Success → `200`.
- Invalid new config → `422` and the **old config keeps serving untouched**.
- Bad or missing token → `401`.
- Listener addresses are not reloadable in v1: a changed `listen` key → `422`.
