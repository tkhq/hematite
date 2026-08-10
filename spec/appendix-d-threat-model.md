# Appendix D — Threat Model Mapping (normative cross-reference)

Every threat from the Phase-1 note, mapped to the design decision that
mitigates it. A decision that maps to no threat is decoration; a threat with
no decision is a hole. Neither exists below.

| # | Threat | Mitigation | Spec |
|---|--------|-----------|------|
| T1 | Exfiltration to a non-allowlisted destination | Default-deny `allowlist` transform; structural, because a config without one fails validation (plus the "first transform" lint) | 04 §1, 09 §3 |
| T2 | SSRF / DNS rebinding: allowlisted name resolving to IMDS/loopback/internal | The guard: deny CIDRs enforced post-resolution at the socket, defaults covering metadata + loopback | 07 §2 |
| T3 | Credential theft from the sandbox | Proxy tokens only inside; swap at egress; `require: true` blocks bring-your-own-credential bypass | 04 §3 |
| T4 | Bypassing the boundary (hardcoded IPs, DoH) | Out of proxy scope by design; nftables/TPROXY deployment recipes | 06 §4, 10 §2 |
| T5 | Secret leakage into logs/annotations/errors | INV-1 (`Secret` type opacity); source-name-only references; vectors C §4 | 00 §5, 04 §3.4, 08 §3 |
| T6 | Policy evasion by encoding: dot segments (raw or percent-encoded), SNI≠Host, tunnel SNI≠target, hop-by-hop smuggling, chunked tricks | Pre-kernel 400s for decoded dot segments and SNI/Host mismatch; tunnel SNI/target agreement; raw-path matching; RFC 7230 strip list; re-framed Content-Length after buffering | 01 §1, 01 §4, 05 §1, 05 §4.3, 07 §3 |
| T7 | CA private-key theft | Deployment concern; spec constrains blast radius: short-lived leaves (72 h), serverAuth-only EKU, minted-per-SNI | 05 §3 |
| T8 | Resource exhaustion: unbounded buffering, slow SNI peek, cert-mint floods, pathological regex | Body caps: over-cap bodies are read-only (streamed in full, transforms see the prefix, rewrites fail closed); 16 KiB/5 s SNI peek bounds; single-flight LRU cert cache; RE2-class regex only | 01 §4, 05 §3–§4, 02 §5 |
| T9 | Config reload races / silent misconfig | Atomic whole-pipeline swap, one pipeline per request; fail-closed 422 keeps old config; unknown keys are validation errors | 03 §1, 09 §3–§4 |
| T10 | Proxy trusts a spoofed upstream | Upstream TLS ≥1.2 verified against system roots, non-disableable in v1 | 07 §4 |

Residual risks accepted in v1 (stated, not hidden): passthrough DNS domains
are invisible to policy (operator's explicit choice, 06 §2); warn mode allows
traffic by definition (04 §1); a root-compromised proxy host defeats
everything (out of scope).
