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

## How Injection Works

For every container of a pod annotated with `cainjekt.tsuzu.dev/enabled: "true"`:

1. **NRI plugin (`CreateContainer`)** stages the CA bundle under `/run/cainjekt/containers/<container-id>/` on the node, adds an OCI `createRuntime` hook and wraps the entrypoint with `/cainjekt-entrypoint`.
2. **OCI hook** (runs on the node before the container starts) detects the distro and merges the CA into the image's trust store inside the container's writable layer. It only touches the container rootfs through a confined API (symlinks are resolved as the container sees them and can never reach the host).
3. **Entrypoint wrapper** (PID 1) sets language-specific variables (e.g. `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`) and `exec`s the original command.

By default every step is **fail-open**: an injection problem is logged and the container starts without (part of) the CA configuration. See `CAINJEKT_FAIL_POLICY`.

## Limitations

- **CA rotation applies to new containers only.** The bundle is copied when a container is created. After updating the ConfigMap, restart workloads (e.g. `kubectl rollout restart`) to pick up the new CA. Running containers keep the old bundle until they are recreated.
- **`kubectl exec`.** Processes started with `kubectl exec` do not go through the entrypoint wrapper. They still see the updated OS trust store; language variables set only by the wrapper are not visible to them (see #9).
- **Read-only root filesystems.** With `readOnlyRootFilesystem: true` the trust store cannot be updated in place.
- **Images that bundle their own trust store** (e.g. Python `certifi`, JVM `cacerts`, statically embedded roots) are only covered where a language processor exists.
- **Only containerd with NRI** is supported (CRI-O NRI is untested).

## License

See LICENSE file for details.
