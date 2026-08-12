# hematite on Kubernetes

This guide covers installing hematite via the Helm chart at
`deploy/chart/hematite/`, steering client pods through the proxy, and
enforcing egress with a NetworkPolicy.

For the full config schema (`values.config`) see
[`docs/configuration.md`](configuration.md).

- [Install](#install)
- [Values reference](#values-reference)
- [Steering clients](#steering-clients)
- [Enforcement](#enforcement)
- [Testing](#testing)

---

## Install

```sh
helm install hematite deploy/chart/hematite -f my-values.yaml
```

The chart deploys one hematite Deployment and Service per namespace. At
minimum, `values.config` must include an `allowlist` transform with at least
one domain or CIDR; hematite refuses to start on an empty allowlist. The
chart's default `values.config` allowlists only `example.invalid` (a
reserved-for-testing name that resolves nowhere), so a default install boots
but egresses nothing. Replace `domains` with your real allowlist before use.

### TLS secret

The https and tunnel listeners require a CA. The Secret must have two keys:
`ca.crt` (PEM certificate) and `ca.key` (PEM private key in PKCS#8 ECDSA
P-256, the only format hematite's TLS library accepts).

For dev or CI, `hack/gen-ca.sh` mints a throwaway CA and creates the Secret
in one step:

```sh
bash deploy/chart/hematite/hack/gen-ca.sh hematite-tls
# or, to target a specific namespace:
bash deploy/chart/hematite/hack/gen-ca.sh hematite-tls -n sandbox
```

Point the chart at that Secret:

```yaml
tls:
  existingSecret: hematite-tls
```

For real deployments, bring a CA managed by your PKI and create the Secret
yourself. The `existingSecret` field is always required when `service.https`
or `service.tunnel` is enabled; the chart does not mint a CA.

### Management secret

The management API uses a bearer token loaded from an environment variable.
Create a Secret with key `apiKey`:

```sh
kubectl create secret generic hematite-mgmt --from-literal=apiKey=<token>
```

Reference it in values:

```yaml
management:
  existingSecret: hematite-mgmt
```

The chart injects it as `HEMATITE_MANAGEMENT_API_KEY`. Your
`values.config` should set `management.api_key_env: "HEMATITE_MANAGEMENT_API_KEY"`.

---

## Values reference

This section covers chart-specific values. For `values.config` itself, see
[`docs/configuration.md`](configuration.md).

### `service`

The Service exposes each hematite listener. Each entry has an `enabled` flag
and a `port`:

```yaml
service:
  clusterIP: ""                           # see below
  dns:        { enabled: false, port: 53 }
  http:       { enabled: true,  port: 80 }
  https:      { enabled: false, port: 443 }
  tunnel:     { enabled: false, port: 8080 }
  management: { enabled: false, port: 9092 }
```

The port is used as both the Service port and the container targetPort, so it
must match the listen address in `values.config`. If `service.http.port: 80`,
then `values.config` must have `proxy.http_listen: ":80"` (or omit it, since
`:80` is the config default).

### `service.clusterIP`

Required when `service.dns.enabled: true`. Set it to a free IP from your
cluster's service CIDR:

```yaml
service:
  clusterIP: 10.43.200.2
  dns: { enabled: true, port: 53 }
```

DNS-steered clients dial the IP that hematite answers with. The chart
templates `Service.spec.clusterIP` and the `HEMATITE_DNS_PROXY_IP` environment
override from this value, so both the Kubernetes Service and the DNS server
advertise the same address. Without a pinned IP, a Service restart could
change the IP and break steering.

### `tls.existingSecret` / `management.existingSecret`

Both fields accept the name of an existing Secret. The chart mounts the TLS
Secret at `/etc/hematite/tls/` and injects `HEMATITE_TLS_CA_CERT` and
`HEMATITE_TLS_CA_KEY` so `values.config` can omit the `tls` block entirely.
The management Secret injects `HEMATITE_MANAGEMENT_API_KEY`.

### Metrics scraping

`GET /metrics` is served on the management port and is auth-exempt. To expose
it, enable the management Service port:

```yaml
service:
  management: { enabled: true, port: 9092 }
```

In `values.config`, the management listener must bind all interfaces so the
Kubernetes Service can forward traffic from outside the pod (spec §4 says
management SHOULD bind loopback for standalone deployments, but in-cluster
scraping requires a pod-routable address):

```yaml
management:
  listen: "0.0.0.0:9092"
  api_key_env: "HEMATITE_MANAGEMENT_API_KEY"

observability:
  metrics:
    enabled: true     # default; can omit
```

Point your Prometheus or metrics collector at `<pod-ip>:9092/metrics`. The
exposition contains only aggregate counters and histograms, with no per-host
labels and no per-request identifiers. A locked-down client that can reach the
management Service port can scrape `/metrics` without a token.

The management Service SHOULD NOT be exposed to untrusted workloads: while
`/metrics` reveals only aggregate traffic shape, `POST /v1/reload` on the same
port can reconfigure the proxy (it still requires bearer auth).

### `env`, `hostAliases`, `extraVolumes`, `extraVolumeMounts`

These are pod-spec passthroughs:

```yaml
env:
  - name: SSL_CERT_FILE
    value: /etc/hematite/tls/ca.crt
```

`SSL_CERT_FILE` is the key one for private upstream CAs. hematite's dialer
verifies upstream TLS against the system trust store. If your upstream uses a
private CA, set `SSL_CERT_FILE` to a PEM file that rustls / rustls-native-certs will pick
up, then mount that file with `extraVolumes`/`extraVolumeMounts`. The k3s
integration test points `SSL_CERT_FILE` at `/etc/hematite/tls/ca.crt`
(the TLS Secret mount) so the MITM CA doubles as the upstream trust anchor.

`hostAliases` adds entries to `/etc/hosts` in the hematite pod. Use it to
route test traffic to a pinned Service IP, keeping it off the real internet.

For secrets sourced from files (the `secrets` transform's `type: file`
source), mount them with `extraVolumes`/`extraVolumeMounts`. Mount at
`/run/hematite-secrets/`; on Debian-based images, `/run/secrets/` collides with
the service-account token projection.

```yaml
extraVolumes:
  - name: internal-token
    secret:
      secretName: hematite-internal-token
extraVolumeMounts:
  - name: internal-token
    mountPath: /run/hematite-secrets
    readOnly: true
```

Then reference the path in `values.config`:

```yaml
config: |
  transforms:
    - name: secrets
      config:
        secrets:
          - source: { type: file, path: "/run/hematite-secrets/internal-token" }
            proxy_value: "proxy-internal-tok"
            match_headers: []
            rules:
              - host: "api.example.com"
```

### `egressLockdown`

An optional NetworkPolicy that limits egress for matched pods to hematite and
cluster DNS:

```yaml
egressLockdown:
  enabled: false
  podSelector: {}
```

When enabled, the chart creates a NetworkPolicy that allows matched pods to
reach hematite on its enabled listener ports, and allows DNS on port 53
UDP+TCP to `kube-system/kube-dns`. All other egress is denied.

**CNI caveat.** NetworkPolicy enforcement depends entirely on the CNI. Stock
k3s includes Flannel with the embedded Network Policy controller, which
enforces this policy. A CNI that ignores NetworkPolicy resources, or a
cluster running without any policy controller, will silently not enforce it:
pods appear to be locked down but can reach anything. Confirm your CNI
enforces NetworkPolicy before relying on this for security.

---

## Steering clients

Clients must be directed to use hematite. Two approaches are practical:

### Explicit proxy

Set `HTTP_PROXY` and `HTTPS_PROXY` on client pods to point at the hematite
Service. Assuming the chart is installed in the same namespace as the client:

```yaml
env:
  - name: HTTP_PROXY
    value: http://hematite:8080
  - name: HTTPS_PROXY
    value: http://hematite:8080
```

This requires `service.tunnel.enabled: true` in your Helm values. The tunnel
listener (port 8080) handles both HTTP and HTTPS via first-byte dispatch:
plain absolute-form requests for HTTP, and CONNECT tunneling for HTTPS.

For HTTPS interception to work, the client must trust the MITM CA. How to
install it depends on the runtime:

- **Node.js**: `NODE_EXTRA_CA_CERTS=/path/to/ca.crt`
- **System trust store** (most Linux images): copy the CA cert into
  `/usr/local/share/ca-certificates/` and run `update-ca-certificates`.

Mount the CA from a ConfigMap or Secret and set the variable from an
initContainer or directly in the pod environment.

This approach is cooperative: a workload that ignores the proxy env vars
bypasses hematite.

### Transparent DNS

Set the client pod's DNS resolver to the hematite Service IP. hematite
answers every query with its own IP (`dns.proxy_ip`), so traffic is
intercepted without the workload cooperating on the proxy protocol.

```yaml
# In the client pod spec:
dnsPolicy: None
dnsConfig:
  nameservers:
    - 10.43.200.2     # service.clusterIP from your values
  searches:
    - default.svc.cluster.local
    - svc.cluster.local
    - cluster.local
```

`service.clusterIP` must be set in your values for this to work: the
`dnsConfig.nameservers` entry must match the stable Service IP exactly.

DNS steering is still cooperative at the socket layer: a workload can
hardcode an IP or use DoH to bypass it. Combine it with `egressLockdown` to
make hematite the only reachable egress path.

---

## Enforcement

**Important:** In Kubernetes, an empty `podSelector` (`{}`) selects **every**
pod in the namespace (including hematite itself, which would block its own
upstream egress). `egressLockdown.podSelector` must always be set to a
non-empty selector that targets only your sandbox pods. The chart will refuse
to render if it is left empty.

Specify a selector that targets your sandbox pods:

```yaml
egressLockdown:
  enabled: true
  podSelector:
    app: sandbox-worker
```

The resulting NetworkPolicy applies a default-deny egress rule to pods
matching that selector, then adds allows for hematite's enabled listener
ports and for cluster DNS. Without this, steering via proxy env vars or DNS is
advisory: a workload that routes around hematite can reach the internet
directly.

`egressLockdown` acts only on pods in the same namespace as the hematite
release. For multi-namespace sandboxes, install one hematite release per
namespace.

**Note:** If `service.management.enabled` is true, the NetworkPolicy also
allows locked-down pods to reach the management port. `GET /metrics` is
auth-exempt on this port (aggregates only, no per-host data; see the metrics
cardinality rationale in [`docs/configuration.md`](configuration.md#observabilitymetrics)).
Consider whether exposing the management port to locked-down pods is
appropriate for your threat model before enabling both together.

---

## Testing

`tests/k3s/run.sh` runs the full acceptance suite on a throwaway cluster.
It requires docker, k3d v5.7.4, helm v3.16.4, kubectl, and openssl. The
script creates a k3d cluster, builds hematite and the acceptance client image
at HEAD, imports both into the cluster, mints a test CA, installs the chart
with `tests/k3s/values.yaml`, and runs the acceptance jobs (steps 1–10).
It then does a `helm upgrade` that removes one allowlisted domain and verifies
hematite picks up the new config (step 11). The
cluster is deleted on exit whether or not the suite passes.

```sh
bash tests/k3s/run.sh
```
