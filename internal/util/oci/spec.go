// Package oci reads the OCI runtime state and bundle spec passed to hooks.
package oci

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	rs "github.com/opencontainers/runtime-spec/specs-go"
)

// LoadSpec reads and parses config.json in bundle and returns its path along
// with the parsed spec.
func LoadSpec(bundle string) (string, *rs.Spec, error) {
	specPath := filepath.Join(bundle, "config.json")
	b, err := os.ReadFile(specPath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read OCI spec %s: %w", specPath, err)
	}
	var spec rs.Spec
	if err := json.Unmarshal(b, &spec); err != nil {
		return "", nil, fmt.Errorf("failed to parse OCI spec %s: %w", specPath, err)
	}
	return specPath, &spec, nil
}

// ResolveRootfsPath returns the rootfs path of the bundle, resolving a
// relative root.path against bundle and defaulting to "rootfs".
func ResolveRootfsPath(bundle string, spec *rs.Spec) string {
	if spec.Root == nil || spec.Root.Path == "" {
		return filepath.Join(bundle, "rootfs")
	}
	if filepath.IsAbs(spec.Root.Path) {
		return spec.Root.Path
	}
	return filepath.Join(bundle, spec.Root.Path)
}
