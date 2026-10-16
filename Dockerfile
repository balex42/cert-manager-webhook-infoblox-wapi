# syntax=docker/dockerfile:1
# Modified by the balex42 fork: pinned Chainguard build and non-root runtime.
# These are multi-platform index digests. Dependabot maintains the pins.
FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/go:latest-dev@sha256:ec623ba822d649d14aa5c07f87545982da7daa482362691f9f5c798e715776f2 AS build

WORKDIR /workspace
COPY go.mod go.sum ./
# Pin the compiler independently of the base image's default Go version.
ENV GOTOOLCHAIN=go1.26.4
RUN go mod download

COPY . .
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -mod=readonly -trimpath -ldflags="-s -w" -o /tmp/webhook .

FROM cgr.dev/chainguard/static:latest@sha256:fe55470f22d3259488d9d3739168d8f04da67755f0b69382bc26eda4a7d3d327
LABEL org.opencontainers.image.source="https://github.com/balex42/cert-manager-webhook-infoblox-wapi" \
      org.opencontainers.image.title="cert-manager Infoblox WAPI webhook" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /tmp/webhook /webhook
COPY LICENSE NOTICE /licenses/
USER 65532:65532
ENTRYPOINT ["/webhook"]
