# smokescreen (Stripe) — non-MITM CONNECT egress proxy with an allowlist
# and a built-in private/link-local deny. No published image; build from
# source at a pinned ref.
FROM golang:1.24-alpine AS build
RUN apk add --no-cache git
RUN go install github.com/stripe/smokescreen@v0.0.4

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /go/bin/smokescreen /usr/local/bin/smokescreen
ENTRYPOINT ["smokescreen"]
