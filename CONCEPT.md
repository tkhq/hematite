# hematite — Concept Note (Phase 1)

*Status: converged. This page is the contract for the spec in `spec/`. Date: 2026-08-10.*

## One-liner

hematite is a default-deny egress boundary for untrusted workloads — a firewall
that speaks HTTP. It sits between a sandbox (CI job, AI agent, container) and
the internet, terminates TLS, enforces an allowlist, swaps proxy tokens for
real credentials at the boundary, and emits a per-request audit record. It is
the same product category as iron-proxy (Go), rebuilt from first principles in
Rust.

## The move

iron-proxy's load-bearing invariants — *real secrets never reach the log*,
*no request reaches the dialer without passing policy*, *every request emits an
audit record* — are enforced by convention: careful code and review discipline.
The single non-obvious reframe of hematite is:

> **The boundary's security invariants are encoded in the type system, not in
> review discipline.**

Concretely: a `Secret` type that implements neither `Display`, `Debug`, nor
`Serialize`, so a secret value *cannot* be formatted into a log line or audit
record — the program that leaks one does not compile. A dialer whose only
entry point consumes the pipeline's `Continue` proof value, so a request
*cannot* reach the network without a policy decision. An `AuditRecord` built from types
that are total (every field serializable, no `unwrap` paths), so every request
*must* produce a record. The spec is written so that each invariant names the
type that enforces it.

## Thesis — the property nobody else can claim

**The boundary is more trustworthy than the workload it guards.** Every
security invariant is machine-checked: either by the type system (secrets,
policy-before-dial, audit totality) or by executable test vectors (matching,
swapping, tracing are pure functions with byte-exact expected outputs). Squid
and Envoy enforce policy through configuration languages interpreted by
general-purpose proxies; iron-proxy enforces it through disciplined Go. Only
hematite can say: *the invariant is a compile error or a failing vector, not a
review comment.* Every contested design decision resolves toward this thesis.

## Stolen mental model

**hematite is a tower middleware stack, lifted to the network boundary.**
The Rust ecosystem already solved layered request processing: `tower::Service`
and `Layer`. hematite generalizes that model from in-process services to
egress: the transform pipeline is a middleware stack, the policy kernel is a
*pure function* `(Config, RequestSummary) → (Verdict, Trace)` with no I/O, and
the network listeners are thin adapters that feed it. Inheriting tower's
answers gives us: composition order semantics, backpressure, and — because the
kernel is pure — determinism, which is what makes test vectors possible.

## Threat model (headline list — full mapping in spec Appendix D)

1. Exfiltration to a non-allowlisted destination (direct, or via open redirect).
2. SSRF / DNS rebinding: an allowlisted hostname resolving to IMDS, loopback, or an internal address at dial time.
3. Theft of credentials from inside the sandbox (mitigated: sandbox only ever holds proxy tokens).
4. Bypass of the boundary entirely — hardcoded IPs, custom resolvers (mitigated outside the proxy: nftables/TPROXY; documented, not implemented).
5. Secret leakage into the audit log, error messages, or annotations.
6. Policy evasion by encoding: dot-segment paths, SNI/Host mismatch, hop-by-hop header smuggling, chunked-encoding tricks.
7. CA private-key theft (deployment concern; spec constrains what the key can sign).
8. Resource exhaustion: unbounded body buffering, slow-client SNI peek, cert-mint floods.
9. Config reload races serving a half-old, half-new policy.

## Scope for v1 (deliberately narrow)

Spec v1 exists to enable ONE MVP implementation — no more.

**In:** HTTP/HTTPS listeners with TLS MITM; DNS interception server; tunnel
listener (absolute-form HTTP, CONNECT, SOCKS5); the transform pipeline; five
transforms (`allowlist` with warn mode, `secrets`, `header_allowlist`,
`annotate`, `body_capture`); secret sources `env` and `file` only; upstream
deny-CIDR guard; JSON audit log; single-endpoint management API (reload);
WebSocket and SSE passthrough.

**Out (explicitly, with a designed extension seam):** the LLM judge transform,
MCP policy/gateway, the PostgreSQL MITM proxy, control-plane managed mode,
response-retry handler, OTEL export, cloud secret sources (AWS, 1Password),
SNI-only passthrough mode, metrics endpoint, HTTP/3.

The rule: we can add scope later from a stable base; we cannot finish an
unbounded first draft.

## Acceptance test (the falsifiable target — spec Appendix A)

One docker-compose scenario, later wired as the integration test. Start
hematite with a known config and CA; from a client whose DNS points at the
proxy:

1. `GET https://httpbin.org/get` (allowlisted) → 200; audit record `action: allow`.
2. `GET https://example.com/` (not allowlisted) → 403; audit `action: reject`, `rejected_by: allowlist`, WARN level.
3. `GET https://httpbin.org/headers` with `Authorization: Bearer proxy-openai-abc123` → upstream sees the real key; audit shows `swapped` annotation, never the real value.
4. Same host with `require: true` and no proxy token → 403 rejected by `secrets`.
5. Request with a disallowed header under `header_allowlist` → header stripped, `stripped_headers` annotated.
6. DNS: static record beats passthrough beats default-intercept; each observed via `dig`.
7. `curl -x` CONNECT tunnel to an allowlisted HTTPS host → MITM'd, transformed, 200.
8. Allowlisted hostname that resolves to `169.254.169.254` → dial refused, audit shows the denied CIDR.
9. `POST /v1/reload` with a config that newly allows example.com → step-2 request now succeeds; reload with an invalid config → 422 and old policy still serves.
10. Every request above produced exactly one audit record that validates against the published JSON Schema, and no record anywhere contains the real secret value.

## Phase 1 exit

One-liner ✓ · The move ✓ · Thesis ✓ · Stolen mental model ✓ · Threat list ✓ ·
Scope boundary ✓ · Acceptance scenario ✓. Phase 2 (drafting) may begin.
