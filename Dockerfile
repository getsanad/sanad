# syntax=docker/dockerfile:1
#
# Multi-stage build for the Sanad services. Produces small, static, non-root images
# suitable for local docker-compose and for a container runtime like ECS Fargate.
#
# One image carries every server binary (gateway, authority, admin) plus the demo upstream
# and the agent-side CLI; each compose service selects its binary via `command:`.

FROM golang:1.25 AS build
WORKDIR /src

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Static, trimmed binaries (CGO off so they run on distroless/static and scratch).
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/ \
    ./cmd/gateway ./cmd/authority ./cmd/admin ./cmd/echomcp ./cmd/passport

# Minimal, non-root runtime with CA roots (for outbound TLS to an IdP/JWKS).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ /usr/local/bin/
# Default to the gateway; compose overrides `command:` for the other services.
CMD ["/usr/local/bin/gateway"]
