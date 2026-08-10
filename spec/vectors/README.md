# spec/vectors — machine-readable Appendix C

These files are the data form of Appendix C; the appendix remains the
human-readable source of truth, and any divergence between the two is a bug.

| file | appendix | level | consumed by |
|---|---|---|---|
| `matching.json` | C §1 | L0 | `hematite-kernel/tests/conformance_matching.rs` |
| `secrets-swap.json` | C §2 | L3 | secrets transform tests (Phase 5) |
| `hop-by-hop.json` | C §3 | L1 | `hematite-proxy` tests (Phase 3) |
| `decision-traces.json` | C §4 | L0 + L3 | `hematite-kernel/tests/conformance_traces.rs` |

Conventions:

- Headers are ordered `[name, value]` pairs — wire order and casing matter
  (Part 01 §1).
- Records are compared after removing every `duration_ms` field (INV-4).
- `config_error: true` rows must be rejected at config load; there is no
  match input for them.
- `$comment` keys are annotations for humans; runners ignore them.
