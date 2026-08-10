# hematite

A default-deny egress boundary for untrusted workloads — a firewall that
speaks HTTP — written in Rust. hematite sits between a sandbox (CI job, AI
agent, container) and the internet: it terminates TLS, enforces an allowlist,
swaps proxy tokens for real credentials at the boundary, and emits one audit
record per request.

Its defining property: **the boundary is more trustworthy than the workload
it guards.** Security invariants are enforced by the type system (a `Secret`
that cannot be logged, a dialer that cannot run without a policy verdict) and
by executable test vectors — not by review discipline.

- Concept note (Phase 1): [`CONCEPT.md`](CONCEPT.md)
- Specification (Phase 2 draft): [`spec/`](spec/README.md)
- Heritage: a from-first-principles redesign of the product category defined
  by [iron-proxy](https://github.com/paradigmxyz/iron-proxy) (Go). Behavioral
  compatibility is a non-goal.

Status: spec v0.1 drafted; implementation not started. Next milestones are in
`spec/README.md` §Status.
