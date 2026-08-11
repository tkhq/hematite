# Part 02 — Matching

*Depends on: Parts 00–01. Conformance: L0.*

All policy in hematite selects requests with the same matcher, the **rule**.
One matching semantics, specified once, shared by every transform and the DNS
server. Test vectors: Appendix C §1.

## 1. Rule

```yaml
- host: "*.example.com"        # domain glob or CIDR (required)
  methods: ["POST", "PUT"]     # optional; absent = any method
  paths: ["/v1/*"]             # optional; absent = any path
```

A rule matches a `RequestSummary` when the host clause matches AND (if
present) some method equals `summary.method` AND (if present) some path
pattern matches `summary.path`. A rule *list* matches when any rule matches
(OR). A **present-but-empty** rule list (`rules: []`) is a config validation
error. Where a part wants "match everything," it grants that meaning to an
**absent** `rules` key (e.g. `header_allowlist`, Part 04 §4), never to an
empty list.

## 2. Domain globs

- Matching is case-insensitive; both pattern and host are compared in
  lowercase ASCII. Hosts are matched without a trailing dot and without a port.
- A pattern with no `*` matches exactly one host.
- `*.example.com` matches `example.com` itself and any subdomain at any
  depth (`a.example.com`, `a.b.example.com`).
- A `*` is only meaningful as the leading label (`*.`); implementations MUST
  reject patterns with `*` elsewhere at config load.
- IDNs are matched in their punycode (A-label) form; implementations MUST NOT
  perform Unicode normalization at match time.

## 3. CIDRs

A host clause in CIDR notation (`10.0.0.0/8`, `fd00::/8`) matches when the
request host is an IP *literal* contained in the prefix. CIDR clauses never
match hostnames; resolution-time IP control is the guard's job (Part 07).
Bare IPs without a prefix length MUST be rejected at config load — write
`/32` (or `/128`) explicitly.

## 4. Path globs

- Patterns match the raw, still-percent-encoded path (Part 01 §1).
- `*` matches any run of characters **including** `/` (so `/v1/*` matches
  `/v1/a/b`). There is no `**`, character class, or `?`.
- A pattern without `*` must equal the path exactly.
- Matching is case-sensitive.

## 5. Header-name patterns

Three transform configs accept header-name entries. `secrets.match_headers`
and `header_allowlist.headers` accept both forms below; `annotate.headers`
accepts literals only (a regex entry there is a config validation error).

- A literal entry matches case-insensitively against the canonicalized header
  name. The casing the request used on the wire MUST be preserved when the
  header is forwarded or rewritten.
- An entry delimited by slashes (`/^x-.*-key$/`) is a case-insensitive
  regular expression (RE2-class semantics: no backreferences, linear time)
  matched against the canonical lowercase header name. Implementations MUST
  reject patterns outside that class at config load (threat T8: pathological
  regex).

## 6. Precedence conventions

Matching itself has no precedence — rules OR together. Where ordered
resolution exists (DNS: static records > passthrough > intercept; pipeline:
transform order), the owning part specifies it. This part defines only
whether a single rule matches.
