#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
CA_FILE=""
IMAGE_TAG="latest"
NAMESPACE="kube-system"

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --ca-file)
      CA_FILE="$2"
      shift 2
      ;;
    --image-tag)
      IMAGE_TAG="$2"
      shift 2
      ;;
    --namespace)
      NAMESPACE="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --ca-file FILE      Path to CA bundle file (required)"
      echo "  --image-tag TAG     Container image tag (default: latest; pin a release, e.g. v1.4.0)"
      echo "  --namespace NS      Kubernetes namespace (default: kube-system)"
      echo "  -h, --help          Show this help message"
      exit 0
      ;;
    *)
      echo -e "${RED}Error: Unknown option $1${NC}"
      exit 1
      ;;
  esac
done

# Validate CA file
if [ -z "$CA_FILE" ]; then
  echo -e "${RED}Error: --ca-file is required${NC}"
  echo "Use --help for usage information"
  exit 1
fi

if [ ! -f "$CA_FILE" ]; then
  echo -e "${RED}Error: CA file not found: $CA_FILE${NC}"
  exit 1
fi

echo -e "${GREEN}Deploying cainjekt to Kubernetes...${NC}"

# Create namespace if it doesn't exist
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# Create ConfigMap from CA file
echo -e "${YELLOW}Creating ConfigMap with CA bundle...${NC}"
kubectl create configmap cainjekt-ca-bundle \
  --from-file=ca-bundle.pem="$CA_FILE" \
  --namespace="$NAMESPACE" \
  --dry-run=client -o yaml | kubectl apply -f -

# Apply ServiceAccount and DaemonSet through kustomize, so the image
# placeholder in daemonset.yaml resolves to ghcr.io/cainjekt/cainjekt:<tag>.
echo -e "${YELLOW}Deploying ServiceAccount and DaemonSet (image tag: ${IMAGE_TAG})...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OVERLAY_DIR="$(mktemp -d)"
trap 'rm -rf "$OVERLAY_DIR"' EXIT
cp "$SCRIPT_DIR/rbac.yaml" "$SCRIPT_DIR/daemonset.yaml" "$OVERLAY_DIR/"
cat > "$OVERLAY_DIR/kustomization.yaml" <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: ${NAMESPACE}
resources:
- rbac.yaml
- daemonset.yaml
images:
- name: cainjekt
  newName: ghcr.io/cainjekt/cainjekt
  newTag: ${IMAGE_TAG}
EOF
kubectl apply -k "$OVERLAY_DIR"

# Wait for DaemonSet to be ready
echo -e "${YELLOW}Waiting for DaemonSet to be ready...${NC}"
kubectl rollout status daemonset/cainjekt -n "$NAMESPACE" --timeout=120s

# Show status
echo -e "${GREEN}Deployment complete!${NC}"
echo ""
echo "Status:"
kubectl get daemonset cainjekt -n "$NAMESPACE"
echo ""
echo "Pods:"
kubectl get pods -n "$NAMESPACE" -l app=cainjekt
echo ""
echo -e "${GREEN}To view logs:${NC}"
echo "  kubectl logs -n $NAMESPACE -l app=cainjekt -f"
echo ""
echo -e "${GREEN}To test CA injection, create a pod with annotation:${NC}"
echo "  cainjekt.tsuzu.dev/enabled: \"true\""
