# Base images are pinned by tag and multi-arch index digest. To bump one, run
#   docker buildx imagetools inspect <image:tag> --format '{{.Manifest.Digest}}'
FROM golang:1.25.14-bookworm@sha256:3b4a11519ad929d1e1d261a12cff056f0c85b735253d7d861346b9c6f8b36437 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -ldflags="-s -w" -trimpath -o cainjekt ./cmd/cainjekt

# Distroless static image (root variant): the NRI plugin runs as uid 0 because
# containerd's NRI socket and the host paths it writes are root-owned. It runs
# with all capabilities dropped (see deploy/kubernetes/daemonset.yaml).
FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2

# Copy the binary from builder
COPY --from=builder /workspace/cainjekt /cainjekt

# The binary runs in different modes:
# - NRI plugin mode (default)
# - Install mode (`cainjekt install --dest <path>`, used by the initContainer
#   to copy the binary to the host)
# - Hook mode (via HOOK_MODE env, run by containerd as an OCI hook)
# - Wrapper mode (via CAINJEKT_WRAPPER_MODE env)
ENTRYPOINT ["/cainjekt"]
