package testutil

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cainjekt/cainjekt/internal/util/containerfs"
)

func WriteExecutableInRootfs(t testing.TB, rootfs, containerPath string) {
	t.Helper()

	hostPath := containerfs.PathInRootfs(rootfs, containerPath)
	if err := os.MkdirAll(filepath.Dir(hostPath), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(hostPath), err)
	}
	if err := os.WriteFile(hostPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(%q): %v", hostPath, err)
	}
}

func EnvValue(env []string, key string) string {
	prefix := key + "="
	for _, e := range env {
		if len(e) > len(prefix) && e[:len(prefix)] == prefix {
			return e[len(prefix):]
		}
	}
	return ""
}

// RunIfContainerfsSupported runs the package's tests only where containerfs
// works (Linux 5.6+ with openat2 RESOLVE_IN_ROOT). Use it from TestMain in
// packages whose tests access a container rootfs; elsewhere (e.g. macOS) the
// package is reported as skipped. CI runs on Linux.
func RunIfContainerfsSupported(m *testing.M) {
	if err := containerfs.CheckSupport(); err != nil {
		fmt.Fprintf(os.Stderr, "SKIP: %v\n", err)
		os.Exit(0)
	}
	os.Exit(m.Run())
}
