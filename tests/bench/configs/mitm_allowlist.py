"""mitmproxy allowlist addon — spirit-equivalent policy: refuse CONNECT to
any host outside the bench allowlist. Published verbatim in the report,
same fairness rule as the other proxies' configs."""

from mitmproxy import http

ALLOWED = {"upstream.test", "stream.test", "llm.test", "imds-test.local"}


def http_connect(flow: http.HTTPFlow) -> None:
    if flow.request.host not in ALLOWED:
        flow.response = http.Response.make(403, b"forbidden by allowlist\n")
