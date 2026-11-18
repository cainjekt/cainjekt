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

### Deploy with Helm

The chart in [charts/cainjekt](charts/cainjekt) deploys the same hardened
DaemonSet (unprivileged, all capabilities dropped, no RBAC). Install it from a
checkout:

```bash
# CA bundle from an existing ConfigMap (default: cainjekt-ca-bundle, key ca-bundle.pem)
kubectl -n kube-system create configmap cainjekt-ca-bundle \
  --from-file=ca-bundle.pem=/path/to/ca-bundle.pem
helm install cainjekt charts/cainjekt -n kube-system --set image.tag=<version>

# ...or let the chart create the ConfigMap from a PEM file
helm install cainjekt charts/cainjekt -n kube-system --set image.tag=<version> \
  --set caBundle.source=inline --set-file caBundle.inline=/path/to/ca-bundle.pem

# ...or use an existing ConfigMap with a different name/key
helm install cainjekt charts/cainjekt -n kube-system --set image.tag=<version> \
  --set caBundle.configMap.name=org-ca --set caBundle.configMap.key=ca.crt
```

`image.tag` defaults to the chart `appVersion` (`latest` until the chart is
released). The image must include the `cainjekt install` subcommand used by the
initContainer.

#### Other values

| Value | Default | Description |
|-------|---------|-------------|
| `failPolicy` | `fail-open` | `CAINJEKT_FAIL_POLICY`; `fail-closed` blocks containers whose injection fails* |
| `hookTimeoutSec` | `20` | `CAINJEKT_HOOK_TIMEOUT_SEC` (2-120)* |
| `logLevel` | `info` | `CAINJEKT_LOG_LEVEL`: `debug`, `info`, `warn`, `error`* |
| `plugin.name` / `plugin.index` | `cainjekt` / `10` | NRI plugin name and index |
| `httpServer.enabled` / `.port` | `false` / `9102` | Pass `--http-addr` for `/healthz`, `/readyz`, `/metrics`** |
| `probes.liveness.enabled` / `probes.readiness.enabled` | `false` | HTTP probes (need `httpServer.enabled`)** |
| `metrics.service.enabled` / `metrics.serviceMonitor.enabled` | `false` | Headless metrics Service / Prometheus Operator ServiceMonitor** |
| `resources`, `tolerations`, `nodeSelector`, `affinity`, `priorityClassName` | see values | Scheduling and resources |
| `podLabels`, `podAnnotations` | `{}` | Extra pod metadata |
| `podSecurityContext`, `securityContext` | hardened | Includes SELinux `spc_t`; see [deploy/kubernetes/README.md](deploy/kubernetes/README.md#privileges) |

\* Takes effect once [#32](https://github.com/cainjekt/cainjekt/pull/32)
(fail policy, hook timeout) and [#33](https://github.com/cainjekt/cainjekt/pull/33)
(log level) are merged; older images ignore these variables.
\*\* Needs a cainjekt image with the HTTP server (`--http-addr`). Not on main
yet, so these are off by default.

See [charts/cainjekt/values.yaml](charts/cainjekt/values.yaml) for all values.

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
