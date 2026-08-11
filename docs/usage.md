# Running hematite

hematite takes one YAML config file and serves the listeners it enables. See
[configuration.md](configuration.md) for the full config reference.

## Build and run

```sh
# From source:
cargo run -p hematite -- -config hematite.yaml

# Or the release binary:
cargo build --release
./target/release/hematite -config hematite.yaml

# Or the container image (published to ghcr.io on tags):
docker run --rm \
  -v $PWD/hematite.yaml:/etc/hematite/hematite.yaml:ro \
  -v $PWD/certs:/etc/hematite/certs:ro \
  -e OPENAI_API_KEY \
  -p 80:80 -p 443:443 -p 8080:8080 -p 53:53/udp \
  ghcr.io/tkhq/test-hematite:v0.1
```

Startup fails fast on any config error. Audit records are written as one JSON
object per line on stderr.

## Deploying as an egress boundary

A full boundary has three moving parts: **DNS steering**, **TLS trust**, and
the **network path**.

### 1. Generate a CA

hematite mints a TLS leaf per hostname signed by an operator CA. Create one
(ECDSA P-256, PKCS#8 key):

```sh
openssl ecparam -name prime256v1 -genkey -noout -out ca.sec1.key
openssl pkcs8 -topk8 -nocrypt -in ca.sec1.key -out ca.key && rm ca.sec1.key
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/CN=hematite CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign" \
  -out ca.crt
```

Point `tls.ca_cert`/`tls.ca_key` at these files.

### 2. Steer DNS at the workload

Set the workload's resolver to hematite's `dns.listen` address and set
`dns.proxy_ip` to the address the workload can reach hematite on. Every
lookup then resolves to the proxy, and traffic arrives at the HTTP/HTTPS
listeners. (In a container, set the container's `dns:` to hematite; on a
host, point `/etc/resolv.conf` at it.)

### 3. Trust the CA in the workload

So the workload accepts the minted leaves, install `ca.crt` in its trust
store — e.g. mount it and run `update-ca-certificates`, or pass
`--cacert ca.crt` / `NODE_EXTRA_CA_CERTS` / `REQUESTS_CA_BUNDLE` per tool.

If hematite dials TLS upstreams that use a **private** CA, that CA must also
be in **hematite's** system trust store, since upstream connections are
verified against the system roots.

### 4. (Optional) tunnel clients

Clients that use an explicit proxy instead of DNS steering can point at
`tunnel_listen` with `CONNECT` (`curl -x http://hematite:8080 …`) or SOCKS5.

### Making the boundary unavoidable

DNS steering is cooperative — a workload can hardcode IPs or use DoH. To make
the boundary mandatory, force all egress through hematite at the network
layer (nftables/TPROXY, a locked-down container network, etc.). hematite is a
userspace boundary and does not enforce this itself.

## Reloading config

With `management.listen` set:

```sh
curl -XPOST -H "Authorization: Bearer $HEMATITE_MANAGEMENT_API_KEY" \
  http://127.0.0.1:9092/v1/reload
```

The new config is validated and swapped atomically; an invalid config is
rejected (`422`) and the running config keeps serving.

## Reading the audit log

One JSON object per request on stderr — action, status, timing, and a trace
of every transform that ran. For example:

```json
{"host":"api.openai.com","method":"POST","path":"/v1/chat/completions",
 "mode":"https","action":"allow","status_code":200,"duration_ms":142.3,
 "request_transforms":[{"name":"allowlist","verdict":"continue"}, …]}
```

Records conform to [`spec/schema/audit-record.schema.json`](../spec/schema/audit-record.schema.json).

## End-to-end example

[`tests/acceptance`](../tests/acceptance) is a runnable docker-compose harness
(proxy + a stand-in upstream + a DNS-steered client) that exercises the whole
boundary — allow/deny, secret swap, the guard, tunnels, DNS precedence, and
reload:

```sh
cd tests/acceptance && ./gen-certs.sh
docker compose up --abort-on-container-exit --exit-code-from client
```
