# Task 8 Report: Docs

## Status: complete

## Commit

`1e7dd3a` — docs: kubernetes deployment guide and README pointer

## What was done

Created `docs/kubernetes.md` covering install (helm install command, TLS secret
shape, gen-ca.sh usage, management secret shape), a values reference section
(service toggles + port coupling, clusterIP pin and DNS-mode requirement,
tls.existingSecret / management.existingSecret, env/hostAliases/extraVolumes/
extraVolumeMounts passthroughs with SSL_CERT_FILE called out, /run/hematite-secrets
mount note, egressLockdown with CNI-enforcement caveat), two client steering
recipes (explicit proxy with CA trust install options, transparent DNS with
dnsPolicy: None + dnsConfig), enforcement section (podSelector scope, per-namespace
requirement), and testing paragraph on tests/k3s/run.sh with prerequisites.

Added the required "Deploy on Kubernetes" section to README.md after the
existing build-and-run content.

## Verification

Cross-checked every values key in the doc against deploy/chart/hematite/values.yaml:

- service.clusterIP, service.dns, service.http, service.https, service.tunnel,
  service.management — all present with matching defaults (dns/https/tunnel/management
  disabled by default, http enabled at 80)
- tls.existingSecret — present, default ""
- management.existingSecret — present, default ""
- env, hostAliases, extraVolumes, extraVolumeMounts — all present, default []
- egressLockdown.enabled — default false, egressLockdown.podSelector — default {}

All commands reference what Tasks 2–7 shipped:
- helm install/upgrade commands match chart location
- gen-ca.sh path matches deploy/chart/hematite/hack/gen-ca.sh
- tests/k3s/run.sh prerequisites match the script header
- Secret key names (ca.crt/ca.key, apiKey) match kubectl create commands in run.sh

## Concerns

None.

---

## Fix round 1

**Commit**: `40c19c6` — docs: explicit-proxy recipe uses the tunnel listener (8080)

**What changed**: In the explicit proxy steering recipe (docs/kubernetes.md, lines 208–218), updated both `HTTP_PROXY` and `HTTPS_PROXY` to point to `http://hematite:8080` instead of `http://hematite:80`. Added prose clarifying that the recipe requires `service.tunnel.enabled: true` and explaining how the tunnel listener (8080) handles both HTTP absolute-form requests and HTTPS CONNECT tunneling via first-byte dispatch.

**Why**: Port 80 is the plain HTTP listener and cannot handle HTTPS CONNECT tunneling. The tunnel listener on port 8080 is required for the explicit-proxy steering approach to work with HTTPS interception. The fix ensures users don't follow a broken recipe and clarifies the infrastructure prerequisite.

---

## Fix wave: final-review findings

| # | Severity | Finding | Fix location |
|---|----------|---------|--------------|
| 1 | Merge-blocking | `docs/kubernetes.md` ~line 262 incorrectly stated that an empty `podSelector` "matches nothing"; in Kubernetes it selects every pod in the namespace, including hematite itself. | Rewrote the Enforcement section opener to state the correct semantics and warn that `podSelector` must always be non-empty. Added a `{{ fail }}` render guard to `deploy/chart/hematite/templates/networkpolicy.yaml` after the `egressLockdown.enabled` gate. Added a negative assertion to `tests/chart/render-test.sh` confirming the template refuses to render with an empty podSelector. |
| 2 | Minor | `docs/kubernetes.md` ~line 136 attributed `SSL_CERT_FILE` to "Go's crypto/tls"; hematite is Rust. | Replaced "Go's crypto/tls" with "rustls / rustls-native-certs" in the `SSL_CERT_FILE` paragraph. |
| 3 | Minor | `deploy/chart/hematite/templates/deployment.yaml` TLS secret volume had no `defaultMode`, leaving `ca.key` world-readable inside the container. | Added `defaultMode: 0400` to the tls secret volume definition. Added a matching positive assertion (`defaultMode: 0400`) to `tests/chart/render-test.sh`. |
| 4 | Minor | `docs/kubernetes.md` egressLockdown section did not warn that `service.management.enabled` exposes the management port to locked-down pods. | Added a **Note** paragraph after the per-namespace note in the Enforcement section. |
| 5 | Minor | `docs/kubernetes.md` ~line 292 step-11 description claimed the removed domain returns 403 "without dropping traffic" — overstating the assertion. | Trimmed "without dropping traffic" from the step-11 sentence. |

**Verification**: `tests/chart/render-test.sh` passes with 19 assertions (all prior checks plus the new `defaultMode` positive check and the empty-podSelector negative check). The full k3s harness was not run — the only template changes (`defaultMode` and the `fail` guard) are fully covered by the render assertions, which exercise helm template evaluation without requiring a live cluster.
