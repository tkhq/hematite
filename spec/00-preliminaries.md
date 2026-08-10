# Part 00 — Preliminaries

*Depends on: nothing. Conformance: all levels.*

## 1. Purpose

hematite is a default-deny egress boundary for untrusted workloads. This
specification defines its observable behavior precisely enough that two
independent implementations agree byte-for-byte on every policy decision,
audit record, and wire transformation covered by the test vectors
(Appendix C).

## 2. Requirement language

MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are used as in RFC 2119. A
sentence without a requirement keyword is informative.

## 3. Terminology

One word per concept. These words are used consistently in every part;
synonyms are defects.

- **workload** — the untrusted client behind the boundary (CI job, agent, container).
- **upstream** — the destination server the workload is trying to reach.
- **operator** — the human or system that authors the configuration.
- **request summary** — the pure-data description of a request that the policy kernel evaluates (Part 01).
- **transform** — one named unit of the pipeline that inspects or rewrites a request/response and returns a verdict (Part 03).
- **pipeline** — the ordered list of transforms (Part 03).
- **verdict** — a transform's per-invocation result: `Continue`, `Reject`, or `Stub` (Part 01).
- **action** — the whole-request outcome recorded in the audit record: `allow`, `reject`, `stub`, `error`, or `client_cancel` (Part 08).
- **rule** — a host/method/path matcher shared by all transforms (Part 02).
- **trace** — the per-transform audit entry: name, verdict, duration, annotations (Part 01).
- **audit record** — the one JSON object emitted per request (Part 08).
- **proxy token** — the placeholder credential the workload holds.
- **secret** — the real credential, known only to hematite (Part 04 §3).
- **guard** — the post-resolution deny-CIDR check at the dialer (Part 07).

## 4. Conformance levels

Levels are cumulative: each level requires everything below it.

| Level | Name | Requires |
|-------|------|----------|
| **L0** | Policy kernel | Parts 01, 02, 03, 04 §1–§2 + §4–§6, 08 §2 (record schema). A pure library: `(config, request summary) → (verdict, traces)`. No network I/O. |
| **L1** | Forward proxy | L0 + Parts 05 §2 (plain-HTTP and absolute-form listeners), 07, 08, 09. Proxies cleartext HTTP with the guard and audit log. |
| **L2** | Transparent boundary | L1 + Parts 05 §3–§5 (TLS MITM, CONNECT, SOCKS5, protocol sniffing), 06 (DNS). The full interception data plane. |
| **L3** | Secret custody | L2 + Part 04 §3 (secrets transform), sources `env` and `file`. |

An implementation MUST state the highest level it claims and MUST pass
exactly the Appendix C vectors for the parts that level requires (each vector
section is level-tagged). Appendix A (the
acceptance test) requires L3.

## 5. Type-enforced invariants

hematite's defining discipline (see `CONCEPT.md`) is that security invariants
are carried by types, not review. The spec states each invariant where it
arises and names it `INV-n`. The four global ones:

- **INV-1 (secret opacity).** The `Secret` type MUST NOT be convertible to a
  loggable or serializable form. No audit record, error message, annotation,
  or trace can contain a secret value. (Rust binding: no `Display` or
  `Serialize` impls and no value-revealing `Debug`; Appendix E.)
- **INV-2 (policy before dial).** No upstream connection may be initiated
  without the `Continue` proof from the pipeline outcome for that request.
  (Rust binding: the dialer's entry point consumes the proof value.)
- **INV-3 (audit totality).** Every accepted client request — including ones
  that fail mid-flight — MUST emit exactly one audit record.
- **INV-4 (kernel purity).** Policy evaluation is deterministic: the same
  config and request summary MUST produce the same verdict and the same
  traces (modulo the `duration_ms` field). This is what makes Appendix C
  possible.

## 6. Relationship to iron-proxy

hematite v1 is behaviorally compatible with iron-proxy's core data plane where
this spec says so, and deliberately narrower everywhere else (Part 10). Where
the two disagree, this spec wins; compatibility is a non-goal.
