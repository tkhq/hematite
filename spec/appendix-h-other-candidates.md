# Appendix H — Other Extension Candidates (Parked Riffs)

*Informative. These are Phase-1-grade riffs, deliberately **not** promoted to
sketches: each records why it is interesting, its hardest problem, and the
seam it would enter through — enough to think with, not enough to build
from. Promotion order is a product decision, not implied by ordering here.*

## H.1 X-judge — LLM allow/deny transform

An operator writes a natural-language policy ("only allow GitHub writes to
repos in our org"); a small LLM renders an allow/deny decision for requests
matching the judge's rules.

- **The interesting part:** policy that static rules cannot express, at the
  cost of nondeterminism inside a spec whose core promise is INV-4. The
  draft's central job is fencing that: the judge is a registry transform
  whose *envelope construction* and *fallback behavior* are deterministic
  and vectorizable, while the LLM verdict itself is marked nondeterministic
  in the trace.
- **Invariants worth keeping from the iron-proxy design:** the judge can
  only reject — static deny always wins, so a hallucinating model can never
  *widen* access. Fallback on error/timeout/breaker-open is `deny` (or
  `skip`, which still lands in default-deny). Envelope caps (body/URL/header
  budgets, priority-ordered headers) bound cost and leakage.
- **Hardest problem:** placement relative to `secrets`. Before secrets, the
  LLM provider sees only proxy tokens (recommended); after, it sees real
  credentials — a threat-model trade the operator must opt into explicitly.
- **Seam:** transform registry (Part 03 §5); provider adapters behind one
  `Complete(system, user) → text` interface.

## H.2 Response-retry handler — externally authorized replay

On configured response statuses (canonically `402 Payment Required`), consult
an external authorization endpoint; it may return headers plus a one-shot
attempt ID authorizing **one exact replay** of the original request; a
completion callback reports the outcome. This is the machinery for
pay-per-request egress and human-in-the-loop unblocking.

- **The interesting part:** it is the only feature where hematite delegates
  a decision *outward* at request time — a trust relationship the core spec
  never has. The invariants are the whole design: response bodies never
  leave the proxy, the destination cannot change, connection/framing headers
  from the handler are rejected, one attempt per ID, over-cap or streaming
  requests are simply non-replayable, and handler failure always yields the
  original response (fail to the status quo, not open).
- **Hardest problem:** the handler endpoint is itself an egress destination
  living inside the deny-CIDR space in real deployments; carving its narrow
  exception without reopening SSRF (threat T2) needs its own threat rows.
- **Seam:** a response-path hook after the upstream responds, before
  response transforms.

## H.3 SNI-only passthrough mode

A `tls.mode: sni-only` where hematite never terminates TLS: it peeks the
ClientHello SNI, evaluates a host-only synthetic summary against the
pipeline, and TCP-splices allowed connections. No CA distribution, no MITM.

- **The interesting part:** the trust trade made explicit. Policy degrades
  to host-level (no paths, headers, or secrets — most transforms cannot
  match), but so does the blast radius of a proxy compromise: there is no CA
  key to steal (retires threat T7 entirely).
- **Hardest problem:** honest conformance. Most of L3 and half of Part 04
  are meaningless in this mode; it is closer to a distinct profile ("P-sni")
  than a config flag, and the spec must stop configs from combining it with
  transforms that silently cannot run. Upstream port pinning (ignore the
  client's port, dial 443) is load-bearing against port-pivot tricks.
- **Seam:** the `tls.mode` key, fixed to `mitm` in v1.

## H.4 Control-plane managed mode

A central service distributes config: the proxy polls with its current
config hash, receives rules/secrets/transform payloads when the hash
differs, plus an identity (principal ID) and an audit-ingest token —
fleet management for many hematites.

- **The interesting part:** it is pure distribution — the data plane never
  changes. Done right, managed mode is *only* a second implementation of
  the config loader plus an audit shipper, which is exactly why Part 09 §2
  step 1 is the seam.
- **Hardest problem:** trust inversion. The control plane becomes a single
  point that can rewrite every boundary's policy; the draft needs signed
  config payloads (or equivalent) so a compromised control plane cannot
  silently disable custody — the thesis applied to hematite's own supply
  chain. Reload semantics (atomic swap, fail-closed on invalid payloads)
  are already specified and reused as-is.
- **Seam:** pluggable config source (Part 09 §2) + an audit-record consumer
  reading the Part 08 line format.

## Not parked

Cloud secret sources (AWS SM/SSM, 1Password) and OTEL export need no riff:
each is a straightforward second implementation of an existing interface
(`SecretResolver`, the audit line format) with no open design questions —
they are scheduling decisions, not design decisions.
