#!/bin/sh
# Compute the container's own IP so the DNS intercept answers point back at
# this proxy, then hand off to hematite. Uses the Part 09 §2 env-override
# mechanism (HEMATITE_DNS_PROXY_IP → dns.proxy_ip).
set -e
export HEMATITE_DNS_PROXY_IP="$(hostname -i | awk '{print $1}')"
echo "hematite: DNS proxy_ip = $HEMATITE_DNS_PROXY_IP"
exec hematite -config /etc/hematite/hematite.yaml
