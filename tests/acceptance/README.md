# Acceptance harness (spec Appendix A)

The executable form of the Appendix A acceptance test: a docker-compose
harness with three services — `hematite`, an `echo` upstream standing in for
`httpbin.org`, and a `client` whose DNS points at the proxy — running the
end-to-end steps that mean "hematite works."

## Run

```sh
./gen-certs.sh                       # one test CA + the echo upstream leaf
docker compose up --abort-on-container-exit --exit-code-from client
```

The client prints each step and exits non-zero on the first failure
(`ACCEPTANCE: PASS` / `FAIL` at the end).

## What each step checks

| Step | Spec | Assertion |
|---|---|---|
| 1 | allow path | allowlisted `GET https://httpbin.org/get` → 200 |
| 2 | default-deny | `https://example.com/` → 403 (rejected by allowlist) |
| 3 | secrets (L3) | upstream sees `Bearer sk-real…`; proxy token never egresses |
| 4 | `require:true` | request without the proxy token → 403 by secrets |
| 5 | header_allowlist | `X-Tracking` stripped before upstream |
| 6 | DNS precedence | static (`10.0.0.9`) beats intercept (proxy IP) |
| 7 | tunnel (L2) | `curl -x` CONNECT → MITM'd 200 |
| 8 | the guard | allowlisted host resolving to `169.254.169.254` → 502 |
| 9 | management | `POST /v1/reload` → 200; bad token → 401 |

Step 10 ("no record contains the real secret", INV-1) is asserted in the
in-process acceptance test (`crates/hematite-proxy/tests/acceptance_inproc.rs`),
which sweeps every emitted audit record; here it is covered observably by
step 3 (the proxy token does not reach the upstream).

## How the trust and steering are wired

- **One test CA** mints the client-facing MITM leaves, signs the echo
  upstream's leaf, and is baked into hematite's system trust store, so
  upstream TLS verification (Part 07 §4) accepts the echo.
- **DNS steering**: the client's resolver is repointed at hematite (its IP is
  discovered via Docker DNS), so every hostname is intercepted to the proxy.
- The proxy's own dialer resolves `httpbin.org` to the echo via a Docker
  network alias; `imds-test.local` is mapped to a metadata address via
  `extra_hosts` to exercise the guard.
- `hematite`'s `dns.proxy_ip` is set at boot to the container's own IP through
  the `HEMATITE_DNS_PROXY_IP` env override (see `entrypoint.sh`).

`certs/` and `secrets/` hold generated throwaway material and are gitignored;
run `./gen-certs.sh` after a fresh checkout.
