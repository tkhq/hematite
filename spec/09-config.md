# Part 09 — Configuration, Validation, Reload

*Depends on: all earlier parts. Conformance: L1 (TLS/DNS keys at L2).*

## 1. Shape

One YAML file, one flag: `hematite -config path.yaml`. Full worked example:
Appendix B. Top-level keys: `dns`, `proxy`, `tls`, `transforms`,
`management`, `log`. Unknown top-level keys or transform names MUST fail
validation (typos must not silently no-op — threat T9).

```yaml
dns:        { enabled, listen, proxy_ip, upstream_resolver, passthrough, records }
proxy:      { http_listen, https_listen, tunnel_listen,
              max_request_body_bytes, max_response_body_bytes,
              upstream_response_header_timeout, upstream_deny_cidrs,
              http_proxy, https_proxy, no_proxy }
tls:        { ca_cert, ca_key, cert_cache_size, leaf_cert_expiry_hours }
transforms: [ { name, config } ]
management: { listen, api_key_env }
log:        { level }
```

## 2. Load order and defaults

1. Parse the YAML file.
2. Apply `HEMATITE_`-prefixed environment overrides. The variable name is the
   config path, uppercased and `_`-joined: `HEMATITE_PROXY_HTTP_LISTEN`.
3. Apply defaults.
4. Validate (§3).

Defaults:

| Key | Default |
|-----|---------|
| `dns.enabled` / `dns.listen` | `true` / `:53` (within a present `dns:` section) |
| `proxy.http_listen` | `:80` |
| `proxy.https_listen` | unset (disabled; requires `tls`) |
| `proxy.tunnel_listen` | unset (disabled) |
| `proxy.max_request_body_bytes` | 1 MiB |
| `proxy.max_response_body_bytes` | 0 (uncapped) |
| `proxy.upstream_response_header_timeout` | 30s |
| `proxy.upstream_deny_cidrs` | metadata + loopback set (Part 07 §2) |
| `tls.cert_cache_size` / `leaf_cert_expiry_hours` | 1000 / 72 |
| `management.api_key_env` | `HEMATITE_MANAGEMENT_API_KEY` |
| `log.level` | `info` |

**Defaults and conformance levels.** A section's defaults apply only when
that section is present: an absent `dns:` block means no DNS server (the
`dns.enabled: true` default is *within* a present block), and the HTTPS and
tunnel listeners are off unless their `listen` key is set. A listener is
served only at the level that defines it (Part 00 §4): an L1 implementation
runs the HTTP listener and ignores any configured HTTPS/tunnel/DNS keys. So
a minimal L1 config — an `allowlist` transform and nothing else — is valid,
and feature-specific validation (`dns.proxy_ip`, `tls.ca_cert`/`ca_key`) is
enforced only when that feature is actually enabled.

## 3. Validation (reject-at-boot, never at request time)

- `dns.proxy_ip` required (IPv4) when DNS enabled; record types A/CNAME only.
- `tls.ca_cert` + `ca_key` required when the HTTPS or tunnel listener is
  enabled; the CA cert MUST have `CA:TRUE` and `keyCertSign`.
- CIDR fields require prefix lengths; globs and header regexes compile
  (Part 02); each transform's own rules (Part 04) hold; `env` secret sources
  resolve non-empty.
- `management.listen` set ⇒ `api_key_env` names a non-empty env var.
- An `allowlist` transform MUST be present (Part 04 §1) — its absence is an
  error, not a lint.
- Ordering lints (warn): `allowlist` first; `body_capture` before body-
  matching `secrets` (Part 04 §6).
- `proxy_value` MUST be RFC 3986 unreserved-only when `match_path` is set
  (Part 04 §3.2).

## 4. Management API and reload

Disabled unless `management.listen` is set; SHOULD bind loopback. One
endpoint:

- `POST /v1/reload`, authenticated with `Authorization: Bearer <token>`
  compared in constant time. Reload re-reads the config file, builds a
  complete new pipeline plus DNS/TLS state, then swaps atomically
  (Part 03 §1). In-flight requests finish on the old pipeline.
- Invalid new config → 422 with the validation error; the old config MUST
  keep serving untouched. Other failures → 500. Success → 200.
- Reload MUST complete even if the requesting client disconnects.

Listener addresses are not reloadable in v1: a changed `listen` key is a 422.
