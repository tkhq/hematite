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
# Apply the echo Deployment+Service first and wait for them to be ready
# before launching the client Job so the echo upstream is reachable.
kubectl apply -f tests/k3s/fixtures.yaml
kubectl rollout status deploy/echo --timeout=180s
kubectl delete job accept-client --ignore-not-found
kubectl apply -f tests/k3s/fixtures.yaml
wait_job accept-client 240
kubectl logs job/accept-client
kubectl logs job/accept-client | grep -q "ACCEPTANCE: PASS"

echo "k3s integration: PASS"
