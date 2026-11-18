package nri

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cainjekt/cainjekt/internal/config"
	"github.com/cainjekt/cainjekt/pkg/certs"
	"github.com/cainjekt/cainjekt/pkg/fsx"
	"github.com/containerd/nri/pkg/api"
)

// pluginTrustStores are candidate CA stores of cainjekt's own image
// (distroless ships one). They seed the merged bundle with public roots so the
// trust-replacing env vars on the container spec resolve to a complete bundle
// from container start, even if the hook never refines it (fail-open).
var pluginTrustStores = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/cert.pem",
}

var unsafePathChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func stageDynamicCAFile(sourceCAFile, root string, ctr *api.Container) (string, error) {
	content, err := os.ReadFile(sourceCAFile)
	if err != nil {
		return "", fmt.Errorf("failed to read source CA file %s: %w", sourceCAFile, err)
	}

	targetDir, err := containerCADir(root, ctr)
	if err != nil {
		return "", err
	}
	// 0755/0644: the directory is bind-mounted into the container, which often
	// runs as non-root. CA certificates are public material.
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create dynamic CA directory %s: %w", targetDir, err)
	}

	if err := os.Chmod(targetDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to chmod dynamic CA directory %s: %w", targetDir, err)
	}

	targetPath := filepath.Join(targetDir, config.DynamicCAFileName)
	if err := fsx.AtomicWrite(targetPath, content, fsx.WriteOptions{
		FallbackMode:  0o644,
		RefuseSymlink: true,
		PreserveOwner: true,
	}); err != nil {
		return "", fmt.Errorf("failed to write dynamic CA file %s: %w", targetPath, err)
	}

	return targetPath, nil
}

// seedMergedCA writes <plugin image roots + org CA> to the merged bundle in
// targetDir. The OCI hook later replaces it with <container's own store + org
// CA>. It returns false (and writes nothing) when the plugin image has no
// roots: a merged bundle with only the org CA would break public TLS for every
// trust-replacing consumer, so callers must then not advertise it.
func seedMergedCA(targetDir string, orgCA []byte) (bool, error) {
	var roots []byte
	for _, p := range pluginTrustStores {
		b, err := os.ReadFile(p)
		if err == nil && len(b) > 0 {
			roots = b
			break
		}
	}
	if roots == nil {
		return false, nil
	}
	merged, err := certs.MergePEM(roots, orgCA)
	if err != nil {
		return false, err
	}
	target := filepath.Join(targetDir, config.MergedCAFileName)
	if err := fsx.AtomicWrite(target, merged.Merged, fsx.WriteOptions{
		FallbackMode:  0o644,
		RefuseSymlink: true,
	}); err != nil {
		return false, fmt.Errorf("failed to write merged CA bundle %s: %w", target, err)
	}
	return true, nil
}

func cleanupDynamicCAFile(root string, ctr *api.Container) error {
	targetDir, err := containerCADir(root, ctr)
	if err != nil {
		return err
	}
	err = os.RemoveAll(targetDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove dynamic CA directory %s: %w", targetDir, err)
	}
	return nil
}

func containerCADir(root string, ctr *api.Container) (string, error) {
	key, err := containerCAKey(ctr)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, key), nil
}

func containerCAKey(ctr *api.Container) (string, error) {
	id := sanitizePathToken(ctr.GetId())
	if id == "" {
		return "", errors.New("container id is empty")
	}
	return id, nil
}

func sanitizePathToken(v string) string {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return ""
	}
	safe := unsafePathChars.ReplaceAllString(trimmed, "_")
	return strings.Trim(safe, "._-")
}

func dynamicCARoot() string {
	return getenvOr(config.EnvDynamicCARoot, config.DefaultDynamicCARoot)
}
