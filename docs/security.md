# hematite security model

This document describes hematite's trust model, the threats it defends
against, what it deliberately does **not** defend against, and how to deploy
it soundly. The normative threat-to-mitigation mapping lives in
[`spec/appendix-d-threat-model.md`](../spec/appendix-d-threat-model.md); this
is the operator-facing companion.

## Trust model

hematite sits between an **untrusted workload** (a CI job, an AI agent, a
container) and the internet. Its thesis is:

> **The boundary is more trustworthy than the workload it guards.**

The workload is assumed to be potentially compromised or actively hostile: it
may try to exfiltrate data, steal credentials, or reach destinations it
shouldn't. hematite's job is to constrain what it can do on the way out.

The trust boundary is drawn so that its core guarantees are
**machine-checked**: the Rust type system and executable test vectors enforce
them, so correctness holds independently of review discipline:

- **Secrets can't be logged.** The `Secret` type implements neither
  `Display`, `Serialize`, nor a value-revealing `Debug`; it is non-`Clone`.
  Code that would format a secret into a log line, audit record, or error
  does not compile.
- **No request reaches the network without a verdict.** The upstream dialer's
  only entry point consumes a proof value that only the policy pipeline can
  produce. There is no code path to a socket that bypasses policy.
- **Every accepted request produces exactly one audit record**, backstopped
  so a panicked or short-circuited handler still emits one.
- **Policy evaluation is deterministic**, which is what lets the same
  decisions be pinned by byte-exact test vectors.

What hematite trusts: the host it runs on, its own configuration and CA key,
and the operator who writes the policy.

## Threats and mitigations

| # | Threat | How hematite mitigates it |
|---|---|---|
| T1 | **Exfiltration to a disallowed destination** | Default-deny `allowlist` is structural: a config without one fails to load. Requests to non-allowlisted hosts get 403. |
| T2 | **SSRF / DNS rebinding** (an allowlisted name resolving to cloud metadata, loopback, or an internal address) | The **guard** checks the *actual resolved IP* at dial time, after resolution; hostname-at-match-time is insufficient. Metadata + loopback are denied by default, so an allowlisted name pointing at `169.254.169.254` still fails at the socket. |
| T3 | **Credential theft from the workload** | The workload only ever holds *proxy tokens*; the `secrets` transform swaps in the real value at egress. `require: true` blocks a compromised workload from bringing its own credentials. |
| T4 | **Bypassing the boundary** (hardcoded IPs, custom resolvers, DoH) | Out of the proxy's scope by design; must be closed at the network layer (see [Deployment responsibilities](#deployment-responsibilities)). |
| T5 | **Secret leakage into logs / audit / errors** | The `Secret` type makes this a compile error; secrets are referred to only by source name. Verified by test vectors and by schema-validated records containing no secret bytes. |
| T6 | **Policy evasion by encoding** (dot-segment paths, SNI≠Host, tunnel SNI≠target, header smuggling, chunked tricks) | Pre-policy 400s for decoded `.`/`..` segments and SNI/Host mismatch; tunnel inner-SNI must equal the CONNECT target; matching is on the raw path; hop-by-hop headers are stripped; framing is re-derived after buffering. |
| T7 | **CA private-key theft** | A deployment concern, but the blast radius is constrained: minted leaves are short-lived (72 h default), `serverAuth`-only, and minted per hostname. |
| T8 | **Resource exhaustion** (unbounded buffering, slow handshakes, cert-mint floods, pathological regex) | Body caps (over-cap bodies stream through read-only); bounded/timed handshake peeking; a single-flight LRU cert cache; RE2-class regex only (linear time). |
| T9 | **Config reload races / silent misconfig** | The whole pipeline is swapped atomically; each request is served start-to-finish by one pipeline instance; an invalid new config is rejected and the old one keeps serving; unknown config keys are load errors. |
| T10 | **Trusting a spoofed upstream** | Upstream TLS is verified against the system roots (TLS ≥ 1.2); verification is mandatory and cannot be disabled in v1. |

## What it protects, concretely

- **Destination control:** only allowlisted hosts/CIDRs are reachable, on
  the real dialed IP.
- **Credential custody:** real secrets live only in hematite; the workload
  and the audit log see placeholders.
- **Header hygiene:** a request-header allowlist plus hop-by-hop stripping;
  the workload's identity is never revealed upstream (no
  `X-Forwarded-For`/`Via`).
- **Full visibility:** one auditable JSON record per request, sufficient to
  reconstruct every policy decision, conforming to a published JSON Schema.

## Residual risks (accepted in v1)

These are accepted, documented trade-offs in v1:

- **Passthrough DNS zones are invisible to policy.** Names matched by
  `dns.passthrough` are forwarded and reached directly; the operator is
  choosing visibility loss explicitly.
- **`warn` mode allows traffic by definition.** An `allowlist` in warn mode
  audits would-be rejections but lets them through; it is a staging aid only,
  with no enforcement effect.
- **A root-compromised proxy host defeats everything.** hematite trusts the
  host it runs on; host compromise is out of scope.
- **DNS steering is cooperative.** On its own it does not stop a determined
  workload (see T4).
- **The CA key is a high-value secret.** Anyone with it can mint trusted
  leaves for any name the workloads trust.

## Deployment responsibilities

hematite is a userspace boundary. Several controls are the deployment's job,
not the proxy's:

1. **Make egress unavoidable.** DNS steering is cooperative. To force *all*
   traffic through hematite, constrain the network: nftables/TPROXY rules, a
   locked-down container network, or an egress-only gateway. Without this, a
   workload can bypass the boundary (T4).
2. **Protect the CA key.** Treat `tls.ca_key` as a top-tier secret: restrict
   file permissions, avoid baking it into images, rotate it if exposed. Its
   blast radius is bounded by short-lived, `serverAuth`-only leaves, but
   theft still lets an attacker impersonate any MITM'd host to the workloads.
3. **Scope the trust store.** Install the hematite CA only in the workloads
   that must trust it. Fleet-wide installation widens the blast radius unnecessarily.
4. **Keep secrets out of config.** Config holds only the *name* of an env var
   or a file path; the config must never hold a secret value. Provide the value via the
   environment or a mounted file with tight permissions.
5. **Bind management to loopback.** The reload endpoint should listen on
   loopback (or an otherwise-restricted interface); its token is compared in
   constant time, but it is still a control-plane surface.
6. **Review `upstream_deny_cidrs`.** The defaults cover cloud metadata and
   loopback. Add your own internal ranges (RFC 1918, service meshes) if the
   workloads should not reach them. Those ranges are outside the default deny list.

## Reporting

This is a v0.1 reference implementation. Security-relevant findings should be
raised as issues (or via private disclosure to the maintainers); please
withhold public exploit details until coordinated.
