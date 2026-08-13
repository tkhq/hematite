# Shared target list for the bench suites (sourced, not executed).
# Every proxy exposes a CONNECT tunnel on :8080; "baseline" is direct.
# shellcheck shell=bash

PROXY_TARGETS="hematite iron squid mitmproxy smokescreen"
ALL_TARGETS="baseline $PROXY_TARGETS"

# Path of the proxy's main binary inside its container ("" = no single
# binary, e.g. mitmproxy's Python distribution).
target_bin() {
  case "$1" in
    hematite)    echo /usr/local/bin/hematite ;;
    iron)        echo /usr/local/bin/iron-proxy ;;
    squid)       echo /usr/sbin/squid ;;
    smokescreen) echo /usr/local/bin/smokescreen ;;
    *)           echo "" ;;
  esac
}

# Capability flags for conformance N/A mapping.
# swap: boundary secret injection; guard: resolved-IP deny of allowlisted
# hosts (squid/mitmproxy lack one — an in-fixture IMDS result for them
# would be a network artifact, not policy); strip: header allowlisting.
target_can() { # target_can <target> <swap|guard|strip>
  case "$1:$2" in
    hematite:swap | iron:swap) return 0 ;;
    hematite:guard | iron:guard | smokescreen:guard) return 0 ;;
    hematite:strip) return 0 ;;
    *) return 1 ;;
  esac
}
