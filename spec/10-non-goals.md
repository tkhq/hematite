# Part 10 — Non-Goals and the Extension Roadmap

*Depends on: Part 00. Conformance: informative, but the boundaries are
normative: a v1 implementation MUST NOT ship §1 items under the v1 label.*

## 1. Out of scope for v1, with a designed seam

Each of these exists in iron-proxy and is deliberately excluded so v1 is
finishable. Each names the seam it would re-enter through, so exclusion is a
decision, not drift.

| Excluded | Why | Re-entry seam | Parked design |
|----------|-----|---------------|---------------|
| LLM judge transform | Nondeterministic by nature — it breaks INV-4 for its trace, needs its own conformance story (fallbacks, breakers) | New registry transform (Part 03 §5), spec level "X-judge" | Appendix H.1 |
| MCP policy + gateway | Body-protocol interception with SSE rewriting; a full sub-spec | A new interceptor stage between pipeline and dialer, "X-mcp" | Appendix G |
| PostgreSQL MITM | A second wire protocol and SQL AST analysis; nothing shared with HTTP path but config and audit | Sibling listener, "X-postgres" | Appendix F |
| Control-plane managed mode | Distribution concern, not data plane | The config loader interface (Part 09 §2 step 1 is pluggable) | Appendix H.4 |
| Response-retry handler | Complex trust delegation; needs its own threat analysis | Response-path hook after upstream, before response transforms | Appendix H.2 |
| Cloud secret sources (AWS SM/SSM, 1Password) | SDK weight; `env`/`file` prove the source abstraction | `SecretSource` trait (Appendix E) | — (Appendix H "Not parked") |
| OTEL export | Downstream of the stable JSON line format (Part 08 §4) | External collector, or "X-otel" emitter | — (Appendix H "Not parked") |
| SNI-only passthrough mode | Superseded: per-domain tunnel passthrough shipped as Part 05 §4.4 (`proxy.tunnel_passthrough_domains`). A global no-MITM mode (`tls.mode`) remains out of scope | `tls.mode` key, currently fixed to `mitm` | Appendix H.3 |
| Metrics endpoint, HTTP/3, warn-mode for transforms other than allowlist | Nice-to-haves | — | — |

Appendices F–H are informative parking lots: enough design to keep each
exclusion honest, none of it normative.

## 2. Permanently out of scope

- **Kernel-level bypass enforcement** (nftables, TPROXY, eBPF): hematite is a
  userspace boundary; making the boundary unavoidable is the deployment's
  job. We document recipes; we do not implement them.
- **Being a general-purpose proxy**: no caching, no load balancing, no
  rewriting for performance, no reverse-proxy mode. Every feature must serve
  the thesis — a trustworthy egress boundary — or it does not enter.
- **Inbound (ingress) protection**: different product.
- **Compatibility with iron-proxy configs**: similar shape by heritage, but
  never a goal (Part 00 §6).
