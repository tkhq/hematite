# Helm Chart + k3s Integration Test Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Helm chart (`deploy/chart/hematite/`) that deploys hematite as a shared egress service, verified by an integration test that installs it on k3s (via k3d) and runs the full acceptance suite plus two Kubernetes-only assertions.

**Architecture:** Single-application chart: Deployment + ClusterIP Service + raw-passthrough ConfigMap, TLS/management material from pre-existing Secrets, optional egress-lockdown NetworkPolicy. The k3s test reuses `tests/acceptance/run.sh` unchanged (two env parameterizations), shipped to an in-cluster client Job via ConfigMap, orchestrated by a bash script that builds images at HEAD and imports them into a throwaway k3d cluster.

**Tech Stack:** Helm 3, k3d/k3s, bash, openssl, GitHub Actions. No Rust changes.

**Spec:** `docs/superpowers/specs/2026-08-10-helm-chart-k3s-design.md`

## Global Constraints

- All bash scripts start with `#!/usr/bin/env bash` and `set -euo pipefail` (the client scripts use `set -uo pipefail` like the existing `run.sh`, because they count failures instead of aborting).
- Pinned versions, referenced everywhere they appear: helm `v3.16.4`, k3d `v5.7.4`, k3s image `rancher/k3s:v1.31.4-k3s1`.
- CA keys are always PKCS#8 ECDSA P-256 (hematite's rcgen 0.13 `KeyPair::from_pem` parses PKCS#8 only — never generate SEC1/RSA keys for it).
- Canonical in-pod paths: config `/etc/hematite/hematite.yaml`, TLS material `/etc/hematite/tls/{ca.crt,ca.key}`.
- Pinned test clusterIPs (k3d's service CIDR is 10.43.0.0/16): hematite Service `10.43.200.2`, echo Service `10.43.200.3`.
- The chart's `values.config` is the literal hematite.yaml (spec Part 09); the chart never re-models config keys. The chart injects only env overrides (`HEMATITE_TLS_CA_CERT`, `HEMATITE_TLS_CA_KEY`, `HEMATITE_DNS_PROXY_IP`, `HEMATITE_MANAGEMENT_API_KEY`) — the env-override mechanism creates missing config sections, so `values.config` may omit the `tls` block entirely.
- Run all commands from the repo root (`hematite/`) unless a step says otherwise.
- Commit after every green test cycle; commit messages follow the repo's `type: summary` convention (see `git log`).

---

### Task 1: Parameterize the acceptance client script

Make `tests/acceptance/run.sh` reusable in-cluster without forking it: the CA path and management token become env vars with defaults preserving compose behavior.

**Files:**
- Modify: `tests/acceptance/run.sh:7` (CA path) and `tests/acceptance/run.sh:76-80` (management token)

**Interfaces:**
- Produces: `run.sh` honors `CA` (default `/certs/ca.crt`) and `MGMT_TOKEN` (default `reload-token`). Task 5's client Job sets `CA=/ca/ca.crt`, `MGMT_TOKEN=reload-token`.

- [ ] **Step 1: Make the edits**

Replace line 7:

```bash
CA=${CA:-/certs/ca.crt}
```

Replace the two step-9 curls (lines 77 and 79) so the good-token call uses the env var:

```bash
code=$(curl -s -o /dev/null -w '%{http_code}' -XPOST -H "Authorization: Bearer ${MGMT_TOKEN:-reload-token}" http://"$PROXY":9092/v1/reload)
```

(the second, bad-token curl keeps its literal `Bearer wrong`).

- [ ] **Step 2: Run the compose acceptance suite to verify no regression**

```bash
cd tests/acceptance && ./gen-certs.sh && docker compose up --build --abort-on-container-exit --exit-code-from client; cd ../..
```

Expected: client prints steps 1–9 and `ACCEPTANCE: PASS`, exit 0.

- [ ] **Step 3: Commit**

```bash
git add tests/acceptance/run.sh
git commit -m "test: parameterize acceptance client CA path and management token"
```

---

### Task 2: Chart core — Chart.yaml, values, Deployment, Service, ConfigMap, render test

The chart skeleton plus a fast render-assertion script that is this task's test cycle (and later CI's fast path). Write the render test FIRST, see it fail, then build templates until it passes.

**Files:**
- Create: `deploy/chart/hematite/Chart.yaml`
- Create: `deploy/chart/hematite/values.yaml`
- Create: `deploy/chart/hematite/templates/_helpers.tpl`
- Create: `deploy/chart/hematite/templates/deployment.yaml`
- Create: `deploy/chart/hematite/templates/service.yaml`
- Create: `deploy/chart/hematite/templates/configmap.yaml`
- Test: `tests/chart/render-test.sh`

**Interfaces:**
- Produces: chart installable as `helm install hematite deploy/chart/hematite -f <values>`; release name `hematite` yields Service/Deployment/ConfigMap all named `hematite` (Task 5 depends on the Service being resolvable as `hematite`). Values schema consumed by Tasks 3–6: `image.{repository,tag,pullPolicy}`, `replicaCount`, `service.clusterIP`, `service.{dns,http,https,tunnel,management}.{enabled,port}`, `config` (string), `resources`, `nodeSelector`, `tolerations`, `affinity`.
- Produces: `tests/chart/render-test.sh` — zero-exit render assertions, extended in Tasks 3–4.

- [ ] **Step 1: Write the failing render test**

`tests/chart/render-test.sh` (make executable: `chmod +x`):

```bash
#!/usr/bin/env bash
# Fast chart checks: helm lint plus grep assertions over `helm template`
# output. No cluster needed; this is CI's fast path for the chart.
set -euo pipefail
cd "$(dirname "$0")/../.."

CHART=deploy/chart/hematite
VALUES=tests/k3s/values.yaml

assert() { # assert <pattern> <description>
  if ! grep -q -- "$1" <<<"$out"; then
    echo "FAIL: rendered output missing: $2 (pattern: $1)"; exit 1
  fi
  echo "ok: $2"
}

out=$(helm template hematite "$CHART" -f "$VALUES")

assert 'clusterIP: 10.43.200.2'        "Service pins the values clusterIP"
assert 'HEMATITE_DNS_PROXY_IP'          "DNS proxy_ip env override present"
assert 'value: "10.43.200.2"'           "proxy_ip env equals the Service clusterIP"
assert 'checksum/config'                "config checksum annotation rolls the Deployment"
assert 'mountPath: /etc/hematite/hematite.yaml' "config mounted at the canonical path"
assert 'protocol: UDP'                  "DNS service port is UDP"

helm lint "$CHART" -f "$VALUES"
echo "chart render checks: PASS"
```

- [ ] **Step 2: Create a minimal `tests/k3s/values.yaml` stub for the render test**

The full test values arrive in Task 5; the render test needs the chart-facing keys now. Create `tests/k3s/values.yaml`:

```yaml
# Values for the k3s integration test install (and the chart render test).
image:
  repository: hematite
  tag: k3s-test
  pullPolicy: Never

service:
  clusterIP: 10.43.200.2
  dns: { enabled: true, port: 53 }
  http: { enabled: true, port: 80 }
  https: { enabled: true, port: 443 }
  tunnel: { enabled: true, port: 8080 }
  management: { enabled: true, port: 9092 }

config: |
  dns:
    enabled: true
    listen: ":53"
    proxy_ip: "10.43.200.2"
  proxy:
    http_listen: ":80"
    https_listen: ":443"
    tunnel_listen: ":8080"
  transforms:
    - name: allowlist
      config:
        domains:
          - "httpbin.org"
  log:
    level: "info"
```

(Task 5 replaces `config` with the full acceptance pipeline; the chart keys stay as-is. Note `tls`/`management` blocks and their existingSecrets are Task 3 — the chart must render without them.)

- [ ] **Step 3: Run the test to verify it fails**

Run: `tests/chart/render-test.sh`
Expected: FAIL (`helm template` errors — chart does not exist yet).

- [ ] **Step 4: Write the chart files**

`deploy/chart/hematite/Chart.yaml`:

```yaml
apiVersion: v2
name: hematite
description: Egress forward proxy for agent sandboxes — default-deny allowlist, TLS MITM, secret swapping, total audit.
type: application
version: 0.1.0
appVersion: "0.1.0"
```

`deploy/chart/hematite/values.yaml`:

```yaml
image:
  repository: ghcr.io/tkhq/hematite
  tag: ""            # defaults to Chart.appVersion
  pullPolicy: IfNotPresent

replicaCount: 1

# The Service is the stable address clients dial. Each entry mirrors a
# listener the config enables; port is used as both Service port and
# container targetPort, so it must match the config's listen ports.
service:
  # Required when service.dns.enabled: a free IP from the cluster's
  # service CIDR. DNS-steered clients dial the IP hematite answers with,
  # and only the Service IP is stable — the chart templates both
  # Service.spec.clusterIP and HEMATITE_DNS_PROXY_IP from this value.
  clusterIP: ""
  dns: { enabled: false, port: 53 }
  http: { enabled: true, port: 80 }
  https: { enabled: false, port: 443 }
  tunnel: { enabled: false, port: 8080 }
  management: { enabled: false, port: 9092 }

tls:
  # Secret with keys ca.crt / ca.key (PKCS#8 ECDSA P-256). Required when
  # the https or tunnel listener is enabled. hack/gen-ca.sh mints a
  # throwaway one for dev/CI.
  existingSecret: ""

management:
  # Secret with key apiKey, exposed as HEMATITE_MANAGEMENT_API_KEY.
  existingSecret: ""

# Literal hematite.yaml (spec Part 09). The chart injects env overrides
# for tls cert paths, dns.proxy_ip, and the management API key, so those
# may be omitted here.
config: |
  proxy:
    http_listen: ":80"
  transforms:
    - name: allowlist
      config:
        domains: []
  log:
    level: "info"

# Extra pod-spec passthroughs.
env: []
hostAliases: []
extraVolumes: []
extraVolumeMounts: []

# Optional default-deny egress NetworkPolicy for client pods: pods
# matching podSelector may egress only to hematite and cluster DNS.
# Requires a NetworkPolicy-enforcing CNI (stock k3s qualifies).
egressLockdown:
  enabled: false
  podSelector: {}

resources: {}
nodeSelector: {}
tolerations: []
affinity: {}
```

`deploy/chart/hematite/templates/_helpers.tpl`:

```yaml
{{- define "hematite.fullname" -}}
{{ .Release.Name }}
{{- end }}

{{- define "hematite.selectorLabels" -}}
app.kubernetes.io/name: hematite
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "hematite.labels" -}}
{{ include "hematite.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}
```

`deploy/chart/hematite/templates/configmap.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "hematite.fullname" . }}
  labels:
    {{- include "hematite.labels" . | nindent 4 }}
data:
  hematite.yaml: |
    {{- .Values.config | nindent 4 }}
```

`deploy/chart/hematite/templates/service.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: {{ include "hematite.fullname" . }}
  labels:
    {{- include "hematite.labels" . | nindent 4 }}
spec:
  type: ClusterIP
  {{- if .Values.service.clusterIP }}
  clusterIP: {{ .Values.service.clusterIP }}
  {{- end }}
  selector:
    {{- include "hematite.selectorLabels" . | nindent 4 }}
  ports:
    {{- if .Values.service.dns.enabled }}
    - name: dns
      port: {{ .Values.service.dns.port }}
      targetPort: {{ .Values.service.dns.port }}
      protocol: UDP
    {{- end }}
    {{- if .Values.service.http.enabled }}
    - name: http
      port: {{ .Values.service.http.port }}
      targetPort: {{ .Values.service.http.port }}
    {{- end }}
    {{- if .Values.service.https.enabled }}
    - name: https
      port: {{ .Values.service.https.port }}
      targetPort: {{ .Values.service.https.port }}
    {{- end }}
    {{- if .Values.service.tunnel.enabled }}
    - name: tunnel
      port: {{ .Values.service.tunnel.port }}
      targetPort: {{ .Values.service.tunnel.port }}
    {{- end }}
    {{- if .Values.service.management.enabled }}
    - name: management
      port: {{ .Values.service.management.port }}
      targetPort: {{ .Values.service.management.port }}
    {{- end }}
```

`deploy/chart/hematite/templates/deployment.yaml` (Task 3 extends the env/volumes blocks; write it with those blocks already present so Task 3 only adds values files — the template below is the FINAL version including TLS/management/passthroughs, so this task's render is already complete):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "hematite.fullname" . }}
  labels:
    {{- include "hematite.labels" . | nindent 4 }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      {{- include "hematite.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "hematite.selectorLabels" . | nindent 8 }}
      annotations:
        checksum/config: {{ .Values.config | sha256sum }}
    spec:
      {{- with .Values.hostAliases }}
      hostAliases:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      containers:
        - name: hematite
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          env:
            {{- if .Values.service.dns.enabled }}
            - name: HEMATITE_DNS_PROXY_IP
              value: {{ required "service.clusterIP must be set when service.dns.enabled (DNS answers must point at the stable Service IP)" .Values.service.clusterIP | quote }}
            {{- end }}
            {{- if .Values.tls.existingSecret }}
            - name: HEMATITE_TLS_CA_CERT
              value: /etc/hematite/tls/ca.crt
            - name: HEMATITE_TLS_CA_KEY
              value: /etc/hematite/tls/ca.key
            {{- end }}
            {{- if .Values.management.existingSecret }}
            - name: HEMATITE_MANAGEMENT_API_KEY
              valueFrom:
                secretKeyRef:
                  name: {{ .Values.management.existingSecret }}
                  key: apiKey
            {{- end }}
            {{- with .Values.env }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
          ports:
            {{- if .Values.service.dns.enabled }}
            - containerPort: {{ .Values.service.dns.port }}
              protocol: UDP
            {{- end }}
            {{- if .Values.service.http.enabled }}
            - containerPort: {{ .Values.service.http.port }}
            {{- end }}
            {{- if .Values.service.https.enabled }}
            - containerPort: {{ .Values.service.https.port }}
            {{- end }}
            {{- if .Values.service.tunnel.enabled }}
            - containerPort: {{ .Values.service.tunnel.port }}
            {{- end }}
            {{- if .Values.service.management.enabled }}
            - containerPort: {{ .Values.service.management.port }}
            {{- end }}
          readinessProbe:
            tcpSocket:
              port: {{ .Values.service.http.port }}
          livenessProbe:
            tcpSocket:
              port: {{ .Values.service.http.port }}
            initialDelaySeconds: 5
          {{- with .Values.resources }}
          resources:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          volumeMounts:
            - name: config
              mountPath: /etc/hematite/hematite.yaml
              subPath: hematite.yaml
              readOnly: true
            {{- if .Values.tls.existingSecret }}
            - name: tls
              mountPath: /etc/hematite/tls
              readOnly: true
            {{- end }}
            {{- with .Values.extraVolumeMounts }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
      volumes:
        - name: config
          configMap:
            name: {{ include "hematite.fullname" . }}
        {{- if .Values.tls.existingSecret }}
        - name: tls
          secret:
            secretName: {{ .Values.tls.existingSecret }}
        {{- end }}
        {{- with .Values.extraVolumes }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
      {{- with .Values.nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.affinity }}
      affinity:
        {{- toYaml . | nindent 8 }}
      {{- end }}
```

- [ ] **Step 5: Run the render test to verify it passes**

Run: `tests/chart/render-test.sh`
Expected: all `ok:` lines, `helm lint` reports 0 failures, `chart render checks: PASS`.

Also sanity-render with the chart's own defaults: `helm template hematite deploy/chart/hematite` — must succeed (no dns enabled → no `required` failure).

- [ ] **Step 6: Commit**

```bash
git add deploy/chart/hematite tests/chart/render-test.sh tests/k3s/values.yaml
git commit -m "feat: helm chart core — deployment, service, config passthrough, render test"
```

---

### Task 3: TLS/management wiring assertions, validation failure, and gen-ca.sh

The Deployment template from Task 2 already renders the TLS/management env and mounts; this task pins that behavior with render assertions, asserts the `required` validation fires, and adds the dev/CI CA helper.

**Files:**
- Create: `deploy/chart/hematite/hack/gen-ca.sh`
- Modify: `tests/chart/render-test.sh` (append assertions)
- Modify: `tests/k3s/values.yaml` (add tls/management/env blocks)

**Interfaces:**
- Consumes: Task 2's chart and render test.
- Produces: `hack/gen-ca.sh <secret-name> [extra kubectl args...]` creates a Secret with keys `ca.crt`/`ca.key` (PKCS#8 ECDSA P-256). Task 5's orchestrator generates its CA inline (it also needs the echo leaf) but Task 7's docs reference this script.

- [ ] **Step 1: Add the failing assertions**

Append to `tests/chart/render-test.sh`, immediately after the existing `assert` lines (still before `helm lint`):

```bash
assert 'HEMATITE_TLS_CA_CERT'           "TLS cert path env override present"
assert 'mountPath: /etc/hematite/tls'   "TLS secret mounted at the canonical path"
assert 'secretName: hematite-tls'       "TLS volume uses tls.existingSecret"
assert 'HEMATITE_MANAGEMENT_API_KEY'    "management API key env present"
assert 'name: hematite-mgmt'            "management key sourced from management.existingSecret"
assert 'name: OPENAI_API_KEY'           "values.env passthrough renders"

# dns.enabled without a pinned clusterIP must refuse to render.
if helm template hematite "$CHART" -f "$VALUES" --set service.clusterIP="" >/dev/null 2>&1; then
  echo "FAIL: expected render error when service.dns.enabled without service.clusterIP"; exit 1
fi
echo "ok: dns.enabled without clusterIP is a render error"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `tests/chart/render-test.sh`
Expected: FAIL at the `secretName: hematite-tls` assertion — the test values don't set the new keys yet.

- [ ] **Step 3: Extend `tests/k3s/values.yaml`**

Add to `tests/k3s/values.yaml` (top level, alongside the existing keys):

```yaml
tls:
  existingSecret: hematite-tls

management:
  existingSecret: hematite-mgmt

env:
  - name: OPENAI_API_KEY
    value: sk-real-acceptance
  - name: SSL_CERT_FILE          # dialer trusts the test CA for the echo upstream
    value: /etc/hematite/tls/ca.crt
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `tests/chart/render-test.sh`
Expected: PASS including the new `ok:` lines.

- [ ] **Step 5: Write `deploy/chart/hematite/hack/gen-ca.sh`** (make executable)

```bash
#!/usr/bin/env bash
# Mint a throwaway MITM CA and create the Secret the chart's
# tls.existingSecret expects. Dev/CI only — bring an operator-managed CA
# for real deployments. Key is PKCS#8 ECDSA P-256, the only format
# hematite's certificate library accepts.
#
#   gen-ca.sh <secret-name> [extra kubectl args, e.g. -n sandbox]
set -euo pipefail
SECRET=${1:?usage: gen-ca.sh <secret-name> [kubectl args...]}
shift
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT

openssl ecparam -name prime256v1 -genkey -noout -out "$dir/ca.sec1.key"
openssl pkcs8 -topk8 -nocrypt -in "$dir/ca.sec1.key" -out "$dir/ca.key"
openssl req -x509 -new -nodes -key "$dir/ca.key" -sha256 -days 30 \
  -subj "/CN=hematite dev CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
  -out "$dir/ca.crt"

kubectl create secret generic "$SECRET" \
  --from-file=ca.crt="$dir/ca.crt" \
  --from-file=ca.key="$dir/ca.key" \
  "$@"
```

- [ ] **Step 6: Test gen-ca.sh without a cluster**

```bash
deploy/chart/hematite/hack/gen-ca.sh hematite-tls --dry-run=client -o yaml | grep -q 'ca.key' && echo "gen-ca: ok"
```

Expected: `gen-ca: ok` (kubectl `--dry-run=client` needs no cluster). Also verify the key format: rerun and pipe the rendered `ca.key` through `base64 -d | head -1` — it must read `-----BEGIN PRIVATE KEY-----` (PKCS#8), not `BEGIN EC PRIVATE KEY`.

- [ ] **Step 7: Commit**

```bash
git add deploy/chart/hematite/hack/gen-ca.sh tests/chart/render-test.sh tests/k3s/values.yaml
git commit -m "feat: chart TLS/management wiring assertions and gen-ca helper"
```

---

### Task 4: Egress-lockdown NetworkPolicy template

**Files:**
- Create: `deploy/chart/hematite/templates/networkpolicy.yaml`
- Modify: `tests/chart/render-test.sh` (append assertions)
- Modify: `tests/k3s/values.yaml` (enable lockdown)

**Interfaces:**
- Consumes: Task 2's helpers and values schema.
- Produces: `egressLockdown.{enabled,podSelector}` values; pods matching `podSelector` may egress only to hematite pods (enabled listener ports) and cluster DNS. Task 5's client Job carries label `app: accept-client` to match.

- [ ] **Step 1: Add the failing assertions**

Append to `tests/chart/render-test.sh` (before `helm lint`):

```bash
assert 'kind: NetworkPolicy'  "egress lockdown renders when enabled"
assert 'app: accept-client'   "lockdown selects the configured client pods"
assert 'k8s-app: kube-dns'    "lockdown allows cluster DNS (bootstrap resolution)"

# Off by default: the chart's own values must NOT render a NetworkPolicy.
if helm template hematite "$CHART" | grep -q 'kind: NetworkPolicy'; then
  echo "FAIL: NetworkPolicy rendered with default values (must be opt-in)"; exit 1
fi
echo "ok: lockdown is off by default"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `tests/chart/render-test.sh`
Expected: FAIL at "egress lockdown renders when enabled".

- [ ] **Step 3: Write the template and enable in test values**

`deploy/chart/hematite/templates/networkpolicy.yaml`:

```yaml
{{- if .Values.egressLockdown.enabled }}
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "hematite.fullname" . }}-egress-lockdown
  labels:
    {{- include "hematite.labels" . | nindent 4 }}
spec:
  podSelector:
    matchLabels:
      {{- toYaml .Values.egressLockdown.podSelector | nindent 6 }}
  policyTypes: ["Egress"]
  egress:
    # Everything goes through hematite...
    - to:
        - podSelector:
            matchLabels:
              {{- include "hematite.selectorLabels" . | nindent 14 }}
      ports:
        {{- if .Values.service.dns.enabled }}
        - port: {{ .Values.service.dns.port }}
          protocol: UDP
        {{- end }}
        {{- if .Values.service.http.enabled }}
        - port: {{ .Values.service.http.port }}
        {{- end }}
        {{- if .Values.service.https.enabled }}
        - port: {{ .Values.service.https.port }}
        {{- end }}
        {{- if .Values.service.tunnel.enabled }}
        - port: {{ .Values.service.tunnel.port }}
        {{- end }}
        {{- if .Values.service.management.enabled }}
        - port: {{ .Values.service.management.port }}
        {{- end }}
    # ...except cluster DNS: clients must resolve the hematite Service
    # name before they can repoint their resolver at it.
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
{{- end }}
```

Add to `tests/k3s/values.yaml`:

```yaml
egressLockdown:
  enabled: true
  podSelector:
    app: accept-client
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `tests/chart/render-test.sh`
Expected: PASS with all lockdown `ok:` lines.

- [ ] **Step 5: Commit**

```bash
git add deploy/chart/hematite/templates/networkpolicy.yaml tests/chart/render-test.sh tests/k3s/values.yaml
git commit -m "feat: optional egress-lockdown NetworkPolicy template"
```

---

### Task 5: k3s harness — fixtures, client wrapper, orchestrator (acceptance steps 1–10)

The integration test proper. Its "test cycle" is running the harness end-to-end locally (needs docker + k3d + helm + kubectl).

**Files:**
- Create: `tests/k3s/client.sh`
- Create: `tests/k3s/fixtures.yaml`
- Create: `tests/k3s/run.sh` (make executable)
- Modify: `tests/k3s/values.yaml` (full config + hostAliases + extraVolumes)

**Interfaces:**
- Consumes: Task 1's parameterized `run.sh` (`CA`, `MGMT_TOKEN` env), Tasks 2–4's chart, `tests/acceptance/{echo.py,client.Dockerfile}` unchanged.
- Produces: `tests/k3s/run.sh` — exits 0 iff install + acceptance steps 1–10 pass. Task 6 appends step 11; Task 7 calls it from CI.

- [ ] **Step 1: Complete `tests/k3s/values.yaml`**

Add `hostAliases` and `extraVolumes`/`extraVolumeMounts`, and replace the stub `config` with the full acceptance pipeline (adapted from `tests/acceptance/hematite.yaml`: `tls` block dropped — env overrides supply the paths; `# upgrade-test-marker` comment added for Task 6's sed-free upgrade):

```yaml
hostAliases:
  - ip: "10.43.200.3"            # echo Service (pinned) stands in for httpbin.org
    hostnames: ["httpbin.org"]
  - ip: "169.254.169.254"        # guard-denial test (spec step 8)
    hostnames: ["imds-test.local"]

extraVolumes:
  - name: internal-token
    secret:
      secretName: hematite-internal-token
extraVolumeMounts:
  - name: internal-token
    mountPath: /run/secrets
    readOnly: true

config: |
  dns:
    enabled: true
    listen: ":53"
    proxy_ip: "10.43.200.2"          # also enforced via HEMATITE_DNS_PROXY_IP
    upstream_resolver: "1.1.1.1:53"
    passthrough:
      - "*.internal.corp"
      - "*.iana.org"
    records:
      - name: "db.internal.corp"
        type: A
        value: "10.0.0.9"

  proxy:
    http_listen: ":80"
    https_listen: ":443"
    tunnel_listen: ":8080"
    max_request_body_bytes: 1048576

  transforms:
    - name: allowlist
      config:
        domains:
          - "httpbin.org"
          - "imds-test.local" # upgrade-test-marker

    - name: annotate
      config:
        annotations:
          - rules:
              - host: "httpbin.org"
            headers: ["x-request-id"]

    - name: body_capture
      config:
        max_request_body_bytes: 16384
        rules:
          - host: "httpbin.org"
            methods: ["POST"]
            paths: ["/anything*"]

    - name: secrets
      config:
        secrets:
          - source: { type: env, var: OPENAI_API_KEY }
            proxy_value: "proxy-openai-abc123"
            match_headers: ["Authorization"]
            require: true
            rules:
              - host: "httpbin.org"
                paths: ["/headers"]
          - source: { type: file, path: "/run/secrets/internal-token" }
            proxy_value: "proxy-internal-tok"
            match_headers: []
            rules:
              - host: "httpbin.org"

    - name: header_allowlist
      config:
        headers:
          - "Authorization"
          - "Accept"
          - "Host"
          - "User-Agent"
          - "Content-Type"
          - "/^x-request-.*$/"
        rules:
          - host: "httpbin.org"

  management:
    listen: "0.0.0.0:9092"
    api_key_env: "HEMATITE_MANAGEMENT_API_KEY"

  log:
    level: "info"
```

- [ ] **Step 2: Write `tests/k3s/client.sh`**

```bash
#!/usr/bin/env bash
# In-cluster client: the full acceptance suite, then the k8s-only
# NetworkPolicy assertion. CA and MGMT_TOKEN come from the Job env.
set -uo pipefail

bash /scripts/run.sh
accept=$?

echo
echo "=== step 10: NetworkPolicy bypass -> blocked ==="
# Dial the echo upstream's Service IP directly, skipping hematite. The
# egress lockdown must make this fail (-k: trust isn't the question).
if curl -s -o /dev/null --max-time 5 -k "https://${ECHO_IP}/get"; then
  echo "  FAIL: direct dial to upstream succeeded (lockdown not enforcing)"
  exit 1
fi
echo "  ok: direct dial blocked"

exit "$accept"
```

- [ ] **Step 3: Write `tests/k3s/fixtures.yaml`**

```yaml
# Echo upstream (stands in for httpbin.org) and the acceptance client Job.
# Secrets/ConfigMaps referenced here are created by tests/k3s/run.sh.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo
  labels: { app: echo }
spec:
  replicas: 1
  selector:
    matchLabels: { app: echo }
  template:
    metadata:
      labels: { app: echo }
    spec:
      containers:
        - name: echo
          image: python:3.12-slim
          command: ["python3", "/echo/echo.py"]
          ports:
            - containerPort: 443
          volumeMounts:
            - { name: script, mountPath: /echo, readOnly: true }
            - { name: certs, mountPath: /certs, readOnly: true }
      volumes:
        - name: script
          configMap: { name: echo-script }
        - name: certs
          secret: { secretName: echo-certs }
---
apiVersion: v1
kind: Service
metadata:
  name: echo
spec:
  clusterIP: 10.43.200.3
  selector: { app: echo }
  ports:
    - port: 443
      targetPort: 443
---
apiVersion: batch/v1
kind: Job
metadata:
  name: accept-client
spec:
  backoffLimit: 0
  template:
    metadata:
      labels: { app: accept-client }   # matched by the egress lockdown
    spec:
      restartPolicy: Never
      containers:
        - name: client
          image: accept-client:test
          imagePullPolicy: Never
          command: ["/bin/bash", "/scripts/client.sh"]
          env:
            - { name: CA, value: /ca/ca.crt }
            - { name: MGMT_TOKEN, value: reload-token }
            - { name: ECHO_IP, value: "10.43.200.3" }
          volumeMounts:
            - { name: scripts, mountPath: /scripts, readOnly: true }
            - { name: ca, mountPath: /ca, readOnly: true }
      volumes:
        - name: scripts
          configMap: { name: accept-scripts }
        - name: ca
          configMap: { name: accept-ca }
```

- [ ] **Step 4: Write `tests/k3s/run.sh`** (make executable)

```bash
#!/usr/bin/env bash
# k3s integration test: build images at HEAD, install the chart on a
# throwaway k3d cluster, run the acceptance suite in-cluster.
# Requires: docker, k3d v5.7.4, helm v3.16.4, kubectl, openssl.
set -euo pipefail
cd "$(dirname "$0")/../.."

CLUSTER=hematite-k3s-test
K3S_IMAGE=${K3S_IMAGE:-rancher/k3s:v1.31.4-k3s1}
tmp=$(mktemp -d)

diagnostics() {
  echo "=== FAILURE DIAGNOSTICS ==="
  kubectl get pods -A -o wide || true
  kubectl describe pods -l app.kubernetes.io/name=hematite || true
  echo "--- hematite logs ---"
  kubectl logs deploy/hematite --tail=200 || true
  echo "--- client job ---"
  kubectl describe job accept-client || true
  kubectl logs job/accept-client --tail=200 || true
}

cleanup() {
  status=$?
  [ "$status" -ne 0 ] && diagnostics
  k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true
  rm -rf "$tmp"
  exit "$status"
}
trap cleanup EXIT

# Poll a Job to Complete (0) or Failed/timeout (1) — `kubectl wait
# --for=condition=complete` hangs on failed jobs.
wait_job() {
  local job=$1 timeout=${2:-180} t=0 s
  while true; do
    s=$(kubectl get job "$job" -o jsonpath='{.status.conditions[?(@.status=="True")].type}' 2>/dev/null || true)
    case "$s" in
      *Complete*) return 0 ;;
      *Failed*)   echo "job/$job failed"; return 1 ;;
    esac
    [ "$t" -ge "$timeout" ] && { echo "job/$job timed out after ${timeout}s"; return 1; }
    sleep 5; t=$((t + 5))
  done
}

echo "=== cluster ==="
k3d cluster create "$CLUSTER" --image "$K3S_IMAGE" --wait --timeout 120s

echo "=== images (built at HEAD) ==="
docker build -t hematite:k3s-test -f Dockerfile .
docker build -t accept-client:test -f tests/acceptance/client.Dockerfile tests/acceptance
k3d image import -c "$CLUSTER" hematite:k3s-test accept-client:test

echo "=== one test CA: MITM leaves + echo upstream leaf ==="
openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/ca.sec1.key"
openssl pkcs8 -topk8 -nocrypt -in "$tmp/ca.sec1.key" -out "$tmp/ca.key"
openssl req -x509 -new -nodes -key "$tmp/ca.key" -sha256 -days 2 \
  -subj "/CN=hematite k3s test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
  -out "$tmp/ca.crt"
openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/echo.key"
openssl req -new -key "$tmp/echo.key" -subj "/CN=upstream" -out "$tmp/echo.csr"
printf 'subjectAltName=DNS:httpbin.org\nextendedKeyUsage=serverAuth\n' > "$tmp/echo.ext"
openssl x509 -req -in "$tmp/echo.csr" -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" \
  -CAcreateserial -days 2 -sha256 -extfile "$tmp/echo.ext" -out "$tmp/echo.crt"
cat "$tmp/echo.crt" "$tmp/ca.crt" > "$tmp/echo.fullchain.crt"

echo "=== secrets and configmaps ==="
kubectl create secret generic hematite-tls \
  --from-file=ca.crt="$tmp/ca.crt" --from-file=ca.key="$tmp/ca.key"
kubectl create secret generic hematite-mgmt --from-literal=apiKey=reload-token
kubectl create secret generic hematite-internal-token \
  --from-literal=internal-token=internal-real-token
kubectl create secret generic echo-certs \
  --from-file=echo.fullchain.crt="$tmp/echo.fullchain.crt" \
  --from-file=echo.key="$tmp/echo.key"
kubectl create configmap echo-script --from-file=echo.py=tests/acceptance/echo.py
kubectl create configmap accept-scripts \
  --from-file=run.sh=tests/acceptance/run.sh \
  --from-file=client.sh=tests/k3s/client.sh
kubectl create configmap accept-ca --from-file=ca.crt="$tmp/ca.crt"

echo "=== install ==="
helm install hematite deploy/chart/hematite -f tests/k3s/values.yaml
kubectl rollout status deploy/hematite --timeout=120s

echo "=== acceptance (steps 1-10) ==="
kubectl apply -f tests/k3s/fixtures.yaml
wait_job accept-client 240
kubectl logs job/accept-client
kubectl logs job/accept-client | grep -q "ACCEPTANCE: PASS"

echo "k3s integration: PASS"
```

- [ ] **Step 5: Run the harness end-to-end**

Run: `tests/k3s/run.sh`
Expected: acceptance steps 1–9 print `ok`, step 10 prints `ok: direct dial blocked`, final line `k3s integration: PASS`, exit 0. On failure, diagnostics dump then non-zero exit. Debug loop notes:
- Chart install errors: `helm template hematite deploy/chart/hematite -f tests/k3s/values.yaml` locally first.
- Step 1–5/7 failures usually mean upstream trust (check `SSL_CERT_FILE` env on the pod) or the `httpbin.org` hostAlias (must be the echo Service IP `10.43.200.3`).
- Step 6 passthrough needs the runner's outbound UDP 53 to 1.1.1.1.
- Step 10 failing "succeeded" means the CNI isn't enforcing NetworkPolicy — confirm the cluster is stock k3s (kube-router netpol controller) and the Job label matches `egressLockdown.podSelector`.

- [ ] **Step 6: Commit**

```bash
git add tests/k3s
git commit -m "test: k3s integration harness — chart install + in-cluster acceptance suite"
```

---

### Task 6: Step 11 — helm upgrade rolls config

**Files:**
- Create: `tests/k3s/fixtures-upgrade.yaml`
- Modify: `tests/k3s/run.sh` (append before the final `PASS` line)

**Interfaces:**
- Consumes: Task 5's harness; the `# upgrade-test-marker` comment on the `imds-test.local` allowlist line in `tests/k3s/values.yaml`.
- Produces: nothing downstream; final harness behavior.

- [ ] **Step 1: Write `tests/k3s/fixtures-upgrade.yaml`**

After the upgrade removes `imds-test.local` from the allowlist, a request for it must be rejected by the allowlist (403) instead of reaching the guard (502):

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: accept-upgrade
spec:
  backoffLimit: 0
  template:
    metadata:
      labels: { app: accept-client }   # same egress lockdown applies
    spec:
      restartPolicy: Never
      containers:
        - name: client
          image: accept-client:test
          imagePullPolicy: Never
          command:
            - /bin/bash
            - -c
            - |
              set -uo pipefail
              PROXY=$(getent hosts hematite | awk '{print $1}' | head -1)
              echo "nameserver $PROXY" > /etc/resolv.conf
              for i in $(seq 1 12); do
                code=$(curl -s -o /dev/null -w '%{http_code}' --cacert /ca/ca.crt https://imds-test.local/)
                [ "$code" = 403 ] && { echo "upgrade roll ok: 403"; exit 0; }
                sleep 5
              done
              echo "FAIL: expected 403 after upgrade, last code: $code"
              exit 1
          volumeMounts:
            - { name: ca, mountPath: /ca, readOnly: true }
      volumes:
        - name: ca
          configMap: { name: accept-ca }
```

- [ ] **Step 2: Append step 11 to `tests/k3s/run.sh`**

Insert before the final `echo "k3s integration: PASS"`:

```bash
echo "=== step 11: helm upgrade rolls config ==="
grep -v 'upgrade-test-marker' tests/k3s/values.yaml > "$tmp/values-upgrade.yaml"
helm upgrade hematite deploy/chart/hematite -f "$tmp/values-upgrade.yaml"
kubectl rollout status deploy/hematite --timeout=120s
kubectl apply -f tests/k3s/fixtures-upgrade.yaml
wait_job accept-upgrade 120
kubectl logs job/accept-upgrade
```

Also add `kubectl logs job/accept-upgrade --tail=50 || true` to the `diagnostics` function.

- [ ] **Step 3: Run the full harness**

Run: `tests/k3s/run.sh`
Expected: steps 1–10 as before, then `upgrade roll ok: 403`, `k3s integration: PASS`, exit 0. (The checksum annotation is what forces the rollout — if `rollout status` returns instantly with no new pods, the annotation isn't wired to `.Values.config`.)

- [ ] **Step 4: Commit**

```bash
git add tests/k3s/run.sh tests/k3s/fixtures-upgrade.yaml
git commit -m "test: assert helm upgrade rolls config into the running proxy"
```

---

### Task 7: CI wiring

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `tests/chart/render-test.sh` (Task 2), `tests/k3s/run.sh` (Task 5/6).

- [ ] **Step 1: Add the jobs**

Append to the `jobs:` map in `.github/workflows/ci.yml` (alongside the existing `test` job):

```yaml
  chart:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: azure/setup-helm@v4
        with:
          version: v3.16.4
      - name: chart render checks
        run: tests/chart/render-test.sh

  k3s-integration:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: azure/setup-helm@v4
        with:
          version: v3.16.4
      - name: install k3d
        run: curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | TAG=v5.7.4 bash
      - name: k3s integration test
        run: tests/k3s/run.sh
```

- [ ] **Step 2: Verify locally what can be verified**

Run: `tests/chart/render-test.sh && tests/k3s/run.sh`
Expected: both PASS (the workflow YAML itself is exercised on push).

- [ ] **Step 3: Commit and push on a branch; watch CI**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: chart render checks + k3s integration job"
git push -u origin HEAD
gh run watch --exit-status || gh run view --log-failed
```

Expected: `test`, `chart`, and `k3s-integration` jobs all green. If `k3s-integration` fails only in CI, pull the diagnostics block from the job log (the harness prints it on failure).

---

### Task 8: Docs

**Files:**
- Create: `docs/kubernetes.md`
- Modify: `README.md` (add a "Deploy on Kubernetes" section pointing at the doc)

**Interfaces:**
- Consumes: everything above; documents only shipped behavior.

- [ ] **Step 1: Write `docs/kubernetes.md`**

Match the tone/structure of the existing `docs/configuration.md`. Required content (write real prose, not this outline):

- **Install**: `helm install hematite deploy/chart/hematite -f my-values.yaml`; TLS Secret prerequisite (`ca.crt`/`ca.key`, PKCS#8 ECDSA P-256) and `hack/gen-ca.sh hematite-tls` for dev; management Secret shape (key `apiKey`).
- **Values reference** (chart-specific only — point at `docs/configuration.md` for `values.config` itself): the `service.*.{enabled,port}` toggles and the rule that ports must match the config's listen ports; `service.clusterIP` pinning and why DNS mode requires it (DNS answers must point at the stable Service IP); `tls.existingSecret` / `management.existingSecret`; `env`/`hostAliases`/`extraVolumes`/`extraVolumeMounts` passthroughs, with `SSL_CERT_FILE` called out for private upstream CAs; `egressLockdown` with the CNI-enforcement caveat (stock k3s enforces; CNIs that ignore NetworkPolicy give silent non-enforcement) and the cluster-DNS allowance.
- **Steering clients**, two recipes:
  - Explicit proxy: `HTTP_PROXY`/`HTTPS_PROXY=http://hematite:8080` env on client pods, CA in the client trust store (`NODE_EXTRA_CA_CERTS` for Node, `update-ca-certificates` for system).
  - Transparent DNS: `dnsPolicy: None` + `dnsConfig: { nameservers: ["<service.clusterIP>"] }` on client pods.
- **Enforcement**: enabling `egressLockdown` with a `podSelector` matching sandbox pods; note that without it, steering is advisory.
- **Testing**: one paragraph on `tests/k3s/run.sh` (throwaway k3d cluster, full acceptance suite, prerequisites).

- [ ] **Step 2: Add the README section**

After the existing usage/deploy content in `README.md`, add:

```markdown
## Deploy on Kubernetes

A Helm chart lives at `deploy/chart/hematite/` — one hematite Deployment +
Service per namespace, with an optional NetworkPolicy that locks client
pods' egress to the proxy. See [docs/kubernetes.md](docs/kubernetes.md).
```

- [ ] **Step 3: Verify docs against reality**

Cross-check every values key mentioned in `docs/kubernetes.md` against `deploy/chart/hematite/values.yaml` (names and defaults must match exactly), and every command against what Tasks 2–6 shipped.

- [ ] **Step 4: Commit**

```bash
git add docs/kubernetes.md README.md
git commit -m "docs: kubernetes deployment guide and README pointer"
```
