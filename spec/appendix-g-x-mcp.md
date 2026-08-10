# Appendix G — Extension Sketch: X-mcp (MCP Policy and Gateway)

*Informative. Nothing here is normative for v1 (Part 10 §1). Parked design;
a real draft would become a numbered part with vectors of its own.*

## What it is

Default-deny policy for the Model Context Protocol's Streamable HTTP
transport. When a request matches a configured MCP server, hematite parses
the JSON-RPC body, enforces a tool allowlist with per-argument constraints,
and filters `tools/list` responses so denied tools never even appear to the
agent. An optional **gateway** layer routes stable internal hostnames to real
MCP upstreams and injects credentials that never enter the sandbox — the
`secrets` custody story at the tool-protocol layer.

## Why it is not a transform (the seam)

MCP responses can be open-ended SSE streams carrying server-initiated
messages; that does not fit the request/response transform contract of Part
03. X-mcp is therefore a distinct **interceptor stage** between the pipeline
and the dialer (Part 10 §1's seam): `allowlist` still gates which hosts are
reachable and `secrets` has already run by the time the interceptor reads the
body. This ordering also means the interceptor sees the wire form that will
actually egress.

## Policy mechanism (derived from the iron-proxy study)

- **Matching.** MCP servers are selected by standard rules (Part 02). Only
  `application/json` POSTs are inspected; the body is parsed as a single
  JSON-RPC object or a batch array, preserving each `id` as raw JSON so
  number/string/null types survive round-tripping.
- **`tools/call` enforcement.** The tool name comes from `params.name`. A
  tool absent from the server's allowlist is denied; a listed tool may carry
  `when` clauses — each a dotted path into the arguments plus one of
  `equals` (scalar), `in` (scalar list), or `matches` (string regex,
  RE2-class per Part 02 §5). Clauses AND together; a missing path fails the
  clause; numeric path segments index arrays, others index objects.
  Malformed JSON-RPC or an over-cap body: deny.
- **Denial shape.** The client sees a normal JSON-RPC *protocol* error —
  configured code/message (default `-32001`, "blocked by hematite policy")
  with the request's original `id` — not an HTTP failure. A batch with any
  denied entry is denied whole (partial forwarding invites confused-deputy
  splits; revisit only with a concrete need).
- **`tools/list` filtering.** Response-side: denied tools are removed before
  the agent sees them. JSON bodies are decoded, filtered, re-encoded. SSE
  bodies are filtered **per event**: each `data:` payload is inspected,
  `tools/list` results (correlated by tracked `id`) are rewritten, and every
  other event — heartbeats, server-initiated messages — passes through
  untouched so long-lived streams stay live.

## Gateway mechanism

Routes apply only to requests the policy has already allowed:

```yaml
mcp_gateway:
  routes:
    - name: github
      rules: [{ host: "github.mcp.local", paths: ["/mcp", "/mcp/*"] }]
      upstream: "https://mcp.github.com/v1"
      credentials:
        - source: { type: env, var: GITHUB_MCP_TOKEN }
          inject: { header: Authorization, formatter: "Bearer {value}" }
```

Credentials reuse the Part 04 §3.1 source abstraction and are required by
default; audit records the route, upstream, and injection *locations* — the
INV-1 machinery already guarantees the values cannot appear.

## Audit

An `mcp` group on the record: server name, per-message entries (direction,
method, tool, decision `allow`/`deny`/`filtered`, denial reason, count of
tools removed), and the applied gateway route.

## Decisions to make before drafting for real

- Coverage beyond tools: `resources/*` and `prompts/*` are unenforced in the
  sketch — an agent can still read resources freely. The real draft must
  either police them or state the gap in its threat rows (iron-proxy ships
  the gap, documented).
- Legacy HTTP+SSE transport (separate `/messages` + `/sse` endpoints):
  support or explicitly refuse.
- Determinism: the policy decision is a pure function of (config, JSON-RPC
  message) — fully vectorizable. SSE filtering is stream rewriting and needs
  its own conformance story (event-sequence vectors, not request vectors).
- Session binding: whether to pin MCP `Mcp-Session-Id` headers to a sandbox
  identity to stop cross-session replay.

## Why it stayed out of v1

It is a body-protocol sub-spec: JSON-RPC parsing, per-event stream
rewriting, and its own audit vocabulary. The seam (interceptor stage +
shared matcher + shared secret sources) is designed; the sub-spec is not.
