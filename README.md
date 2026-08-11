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

- Usage guide: [`docs/usage.md`](docs/usage.md) — running and deploying
- Configuration reference: [`docs/configuration.md`](docs/configuration.md) — every config key
- Security model & threat model: [`docs/security.md`](docs/security.md)
- Concept note (Phase 1): [`CONCEPT.md`](CONCEPT.md)
- Specification (Phase 2): [`spec/`](spec/README.md)
- Heritage: a from-first-principles redesign of the product category defined
  by [iron-proxy](https://github.com/paradigmxyz/iron-proxy) (Go). Behavioral
  compatibility is a non-goal.

## Workspace

Each crate is a conformance-level boundary (spec Appendix E):

| Crate | Level | Scope |
|-------|-------|-------|
| [`hematite-kernel`](crates/hematite-kernel) | L0/L3 | pure policy kernel — decision model, matching, pipeline, transforms, secret custody |
| [`hematite-proxy`](crates/hematite-proxy) | L1/L2 | listeners (HTTP, HTTPS MITM, tunnel), guard, upstream TLS, audit, config/reload |
| [`hematite-dns`](crates/hematite-dns) | L2 | DNS interception server |
| [`hematite`](crates/hematite) | — | the binary |

## Build and run

```sh
cargo test --workspace          # unit + conformance vectors + integration
cargo run -p hematite -- -config hematite.yaml

# Container image (also published to ghcr.io on push to main):
docker build -t hematite .
```

The end-to-end acceptance test (spec Appendix A) runs under
[`tests/acceptance`](tests/acceptance):

```sh
cd tests/acceptance && ./gen-certs.sh
docker compose up --abort-on-container-exit --exit-code-from client
```

Status: spec v0.1 and a full v1 implementation (L0–L3) — all conformance
vectors, the acceptance test, and the container harness pass. Milestones in
`spec/README.md` §Status.
