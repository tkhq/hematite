# Helm chart + k3s integration test — design

Date: 2026-08-10
Status: approved for planning

## Goal

Make Kubernetes the MVP deployment target for hematite:

1. A Helm chart in this repo that deploys hematite as a shared egress
   service for a namespace.
2. An integration test that installs the chart on k3s (via k3d) and runs
   the full acceptance suite against it, in CI and locally.

The valet-v2 integration informed this design but is out of scope; the
chart is the artifact valet (or any consumer) will install.

## Decisions

| Decision | Choice |
|---|---|
| Topology | Shared egress service: one Deployment + Service per namespace. No sidecar mode. |
| CA handling | `tls.existingSecret` for real deployments; `tls.generate: true` mints a throwaway CA with Helm `genCA` for dev/CI. |
| Config surface | Raw passthrough: `values.config` is literal hematite.yaml (spec Part 09 stays the single schema source). |
| Enforcement | Optional NetworkPolicy template, off by default. |
| Test harness | k3d + bash/helm orchestrator script; identical locally and in CI. |
| Test scope | Reuse the full acceptance suite (`tests/acceptance/run.sh`) plus two k8s-only assertions. |

## Chart: `deploy/chart/hematite/`

Chart version starts at `0.1.0`; `appVersion` tracks the crate version.
Chart publishing (OCI push to ghcr) is a follow-up, not MVP.

### Deployment

- 1 replica by default; ghcr image (`values.image.*`), args
  `-config /etc/hematite/hematite.yaml`.
- Config mounted from the ConfigMap; a checksum annotation on the pod
  template rolls the Deployment on `helm upgrade` when config changes.
- Readiness/liveness: probe the management listener when enabled,
  otherwise a TCP probe on the http port.
- No RBAC beyond the default ServiceAccount — hematite does not talk to
  the Kubernetes API.

### Service

- ClusterIP Service, name defaults to `hematite`.
- Ports gated by `values.service.*` toggles that mirror which listeners
  the config enables: 53/UDP (dns), 80 (http), 443 (https), 8080
  (tunnel), 9092 (management).

### DNS-steered mode and the Service IP

Clients that resolve through hematite must dial the answer hematite
returns, and in the shared-service topology the stable dialable address
is the **Service clusterIP**, not the pod IP. The downward API cannot
expose the Service IP, so:

- When `values.service.dns.enabled` is true, the chart REQUIRES
  `values.service.clusterIP` to be set (a pinned IP from the cluster's
  service CIDR). The chart templates both `Service.spec.clusterIP` and
  the `HEMATITE_DNS_PROXY_IP` env override from that single value.
- When DNS mode is off, `HEMATITE_DNS_PROXY_IP` is not set and
  `service.clusterIP` may be left for the cluster to allocate.

### ConfigMap (raw passthrough)

`values.config` is the literal hematite.yaml content per spec Part 09.
The chart auto-injects only what it must, via env overrides (which apply
after YAML parse, per Part 09):

- `HEMATITE_TLS_CA_CERT=/etc/hematite/tls/ca.crt` and
  `HEMATITE_TLS_CA_KEY=/etc/hematite/tls/ca.key` when TLS is configured,
  so `values.config` never needs to know mount paths.
- `HEMATITE_DNS_PROXY_IP` as above.
- `HEMATITE_MANAGEMENT_API_KEY` from `values.management.existingSecret`.

### TLS Secret

- `values.tls.existingSecret`: name of a Secret with keys `ca.crt` and
  `ca.key` (PKCS#8 ECDSA P-256 per spec), mounted read-only at
  `/etc/hematite/tls`.
- `values.tls.generate: true`: chart creates the Secret itself using
  Helm `genCA`, guarded with `lookup` so an upgrade reuses the existing
  Secret instead of re-minting (clients that trusted the old CA keep
  working). Dev/CI convenience only; documented as such.
- Setting both is a values validation error (`fail` in the template).

### Optional NetworkPolicy (`values.egressLockdown`)

- `enabled: false` by default.
- When enabled: a default-deny-egress NetworkPolicy selecting pods via
  `values.egressLockdown.podSelector`, with egress allowed only to (a)
  the hematite pods on the enabled listener ports plus 53/UDP and (b)
  cluster DNS (kube-dns/CoreDNS) on 53/UDP+TCP. Without (b), a client
  could never resolve the hematite Service name in the first place.
- README caveat: enforcement requires a NetworkPolicy-capable CNI.
  Stock k3s enforces via its embedded kube-router policy controller;
  clusters whose CNI ignores NetworkPolicy get silent non-enforcement.

### hostAliases

`values.hostAliases` passes through to the pod spec. Needed by the test
(and useful generally) to steer hematite's own upstream dialing without
external DNS.

## Acceptance script parameterization

`tests/acceptance/run.sh` gains two env-var parameterizations, with
defaults preserving today's compose behavior. No fork of the script.

- `CA=${CA:-/certs/ca.crt}`
- `MGMT_TOKEN=${MGMT_TOKEN:-reload-token}` replacing the hardcoded
  literal in step 9.

Proxy discovery (`getent hosts hematite`) already works in-cluster: a
Service named `hematite` in the client's namespace resolves identically.

## k3s integration test: `tests/k3s/`

Files:

- `run.sh` — orchestrator (runs on the host: macOS dev box or CI runner)
- `values.yaml` — chart values for the test install
- `fixtures.yaml` — echo upstream + client Job manifests
- `client.sh` — in-cluster wrapper: executes the acceptance script, then
  the k8s-only step 10

### Orchestrator flow (`run.sh`)

1. `k3d cluster create hematite-test` with a pinned k3s image version.
2. `docker build` the prod Dockerfile, `k3d image import` — the test
   exercises source at HEAD, not the last published image.
3. `helm install hematite deploy/chart/hematite -f tests/k3s/values.yaml`.
4. `kubectl apply -f tests/k3s/fixtures.yaml`; the acceptance scripts are
   shipped to the client Job via a ConfigMap created from the real files
   (`kubectl create configmap --from-file`), so compose and k3s always
   run identical assertion code.
5. Wait for the client Job, stream logs, record pass/fail.
6. Step 11 (upgrade roll): `helm upgrade` with one allowlist domain
   removed from `values.config`, wait for rollout, run a second
   short-lived Job asserting that domain now returns 403.
7. Teardown via `trap`: on failure, first dump `kubectl describe` for
   hematite/client pods and hematite logs; always
   `k3d cluster delete hematite-test`.

`set -euo pipefail` throughout; every wait has a timeout.

### Test values (`tests/k3s/values.yaml`)

- All listeners enabled; `tls.generate: true`.
- `service.dns.enabled: true` with a pinned `service.clusterIP` from
  k3d's default service CIDR (10.43.0.0/16).
- `values.config` inlines the same transform pipeline as
  `tests/acceptance/hematite.yaml` (allowlist, secrets swap with
  `OPENAI_API_KEY=sk-real-acceptance` env on the Deployment, header
  strip, DNS static/passthrough records) so acceptance steps 1–9 behave
  identically.
- `egressLockdown.enabled: true`, podSelector matching the client Job's
  label.
- `hostAliases`: `httpbin.org` → the echo Service's pinned clusterIP;
  `imds-test.local` → `169.254.169.254` (equivalent of compose's network
  alias and `extra_hosts`).

### Fixtures (`fixtures.yaml`)

- Echo upstream: the same python image/server as compose, as a
  Deployment + Service with a pinned clusterIP (referenced by the
  hematite hostAliases).
- Client Job: same client image as compose, labeled to match the
  egressLockdown selector, resolver pointed at the hematite Service
  (the script repoints `/etc/resolv.conf` itself, as today), runs
  `client.sh` from the ConfigMap with `CA`/`MGMT_TOKEN` env set.

### k8s-only assertions

- **Step 10 — NetworkPolicy enforcement** (in `client.sh`): curl with
  `--max-time 5` straight to the echo Service clusterIP, bypassing
  hematite; the connection must fail. Proves lockdown is enforcing, not
  advisory.
- **Step 11 — upgrade config roll** (orchestrator-side): described in
  the flow above. Proves config changes ship via `helm upgrade` and the
  checksum-annotation roll works.

## CI

- New `k3s-integration` job in `.github/workflows/ci.yml` on
  `ubuntu-latest`: install pinned k3d/helm, run `tests/k3s/run.sh`.
  Runs on PRs and main alongside test/clippy/fmt.
- Fast path: `helm lint` and a `helm template` render check (with the
  test values) added to the existing quick CI jobs, so chart syntax
  errors fail in seconds, not after a cluster boot.

## Docs

- `docs/kubernetes.md`: install command, chart-specific values reference
  (TLS secret shape, `egressLockdown`, pinned clusterIP for DNS mode),
  and two client-steering recipes: proxy env vars
  (`HTTP_PROXY`/`HTTPS_PROXY` → tunnel listener) and transparent DNS
  (`dnsPolicy: None` + `dnsConfig.nameservers: [<service clusterIP>]`).
- README: short "Deploy on Kubernetes" section pointing at the doc.

## Out of scope

- Sidecar topology, cert-manager integration, chart publishing to ghcr,
  HA/multi-replica concerns (DNS answers vs per-pod state), and the
  valet-v2 integration spec (separate effort; consumes this chart).
