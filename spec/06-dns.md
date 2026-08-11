# Part 06 — DNS Server

*Depends on: Parts 00, 02. Conformance: L2.*

The DNS server is what makes interception transparent: the workload's
resolver points at hematite, every lookup answers with the proxy's IP, and
traffic arrives at the listeners without client cooperation.

## 1. Config

```yaml
dns:
  enabled: true                # default true; false disables the server
  listen: ":53"
  proxy_ip: "172.20.0.2"       # required when enabled; IPv4
  upstream_resolver: "1.1.1.1:53"   # optional; default 1.1.1.1:53
  passthrough: ["*.internal.corp"]  # domain globs (Part 02 §2)
  records:
    - { name: "internal.example.com", type: A, value: "10.0.0.5" }
```

## 2. Resolution precedence

For each query name (lowercased, FQDN-normalized), in order:

1. **Static records** — exact-name match; highest precedence. Types `A` and
   `CNAME` only; a config with any other type MUST fail validation. A
   matching `CNAME` record is returned as a single CNAME answer without
   chasing the target: the server does not resolve the target itself, and
   the client re-queries the canonical name (which the same precedence then
   handles). A matching `A` record answers `A`; a name that exists only as
   another type answers empty NOERROR.
2. **Passthrough** — if the name matches any passthrough glob, forward the
   query to the upstream resolver and relay its answer. Traffic to these
   hosts bypasses the proxy entirely; the operator is choosing visibility
   loss explicitly.
3. **Intercept (default)** — answer `A → proxy_ip`.

## 3. Behavior details

- Answer TTL is fixed at 60 seconds for static and intercept answers.
- `AAAA` queries for intercepted names MUST return an empty NOERROR answer
  (not NXDOMAIN), so dual-stack clients fall back to the A record instead of
  concluding the name does not exist. Other query types (MX, TXT, SRV, …)
  for intercepted names likewise return empty NOERROR.
- Upstream resolver queries MUST carry a timeout (5 s); on failure return
  SERVFAIL. The upstream resolver defaults to a concrete public resolver
  (`1.1.1.1:53`), not the host's OS resolver: inside an intercepted network
  the OS resolver may point back at hematite, which would loop.
- UDP and TCP on the listen port MUST both be served.

## 4. Interception is cooperative (informative)

DNS steering is easy to bypass (hardcoded IPs, DoH). Enforcement — nftables
egress rules, TPROXY — is deliberately outside hematite (Part 10 §2);
deployment recipes belong in operator docs, mirroring iron-proxy's.
