# cainjekt

CA certificate injection tool for Kubernetes using NRI (Node Resource Interface).

## Features

- 🔒 Inject custom CA certificates into containers at runtime
- 🚀 Uses containerd NRI for transparent integration
- 🎯 Per-container dynamic CA bundle staging
- 🐧 Supports multiple OS distributions (Debian, Ubuntu, Alpine, etc.)
- 📦 Minimal container image based on distroless (~15MB)
- 🏗️ Multi-architecture support (amd64, arm64)

## Quick Start

### Deploy to Kubernetes

```bash
# Pull pre-built image from GitHub Container Registry
docker pull ghcr.io/cainjekt/cainjekt:latest

# Deploy using kustomize
kubectl apply -k deploy/kubernetes/

# Or use the deployment script
cd deploy/kubernetes
./deploy.sh --ca-file /path/to/ca-bundle.pem
```

See [deploy/kubernetes/README.md](deploy/kubernetes/README.md) for detailed deployment instructions.

### Enable CA injection for a pod

Add the annotation to your pod:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
  annotations:
    cainjekt.tsuzu.dev/enabled: "true"
spec:
  containers:
  - name: app
    image: my-app:latest
```

## Health and Metrics

The plugin serves HTTP on `--http-addr` (default `:9102`; empty disables it):

- `GET /healthz`: 200 while the process is alive.
- `GET /readyz`: 200 only while connected to and synchronized with containerd, 503 otherwise.
- `GET /metrics`: Prometheus metrics (plus Go and process collectors).

| Metric | Type | Description |
|---|---|---|
| `cainjekt_containers_injected_total` | counter | Containers set up for CA injection |
| `cainjekt_containers_skipped_total{reason}` | counter | Containers started without injection (`not_enabled`, `injection_error`) |
| `cainjekt_injection_errors_total` | counter | CA staging failures, under any fail policy |
| `cainjekt_orphan_dirs_cleaned_total` | counter | Staged CA directories removed for vanished containers |
| `cainjekt_nri_connected` | gauge | 1 while connected and synchronized with the runtime |
| `cainjekt_nri_reconnects_total` | counter | Reconnects after the runtime connection was lost |
| `cainjekt_ca_bundle_certificates` | gauge | Parseable certificates in the source CA bundle |
| `cainjekt_ca_bundle_earliest_expiry_timestamp_seconds` | gauge | Earliest NotAfter in the bundle (Unix time) |
| `cainjekt_ca_bundle_info{sha256}` | gauge | Always 1; label is the bundle's short SHA-256 |
| `cainjekt_ca_bundle_read_errors_total` | counter | Failed periodic reads of the source CA bundle |

The CA bundle gauges are refreshed every minute and on every injection. Example
expiry alert: `cainjekt_ca_bundle_earliest_expiry_timestamp_seconds - time() < 14 * 86400`.

## Container Images

Pre-built images are available on GitHub Container Registry:

- `ghcr.io/cainjekt/cainjekt:latest` - Latest main branch
- `ghcr.io/cainjekt/cainjekt:v1.0.0` - Specific version
- `ghcr.io/cainjekt/cainjekt:main-<sha>` - Specific commit

Both `linux/amd64` and `linux/arm64` platforms are supported.

## Building from Source

```bash
# Build binary
make build

# Build Docker image
make docker-build

# Build and load into kind cluster
make kind-load
```

## Requirements

- Kubernetes cluster with containerd runtime
- containerd v2.0+ (NRI enabled by default) or v1.x with NRI manually enabled
- CA certificate bundle to inject

## License

See LICENSE file for details.
