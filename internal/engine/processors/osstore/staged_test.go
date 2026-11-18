package osstore

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cainjekt/cainjekt/internal/config"
	hookapi "github.com/cainjekt/cainjekt/internal/engine/api"
	"github.com/cainjekt/cainjekt/pkg/certs"
)

func stagedCtx(t *testing.T, rootfs string) (*hookapi.Context, string) {
	t.Helper()
	staged := t.TempDir()
	caFile := filepath.Join(staged, config.DynamicCAFileName)
	if err := os.WriteFile(caFile, mustCreateTestCertPEM(t), 0o644); err != nil {
		t.Fatal(err)
	}
	return &hookapi.Context{
		Rootfs:         rootfs,
		CAFile:         caFile,
		ContainerCADir: config.ContainerCADir,
		Facts:          hookapi.NewMapFactStore(),
	}, staged
}

func writeStore(t *testing.T, rootfs string) {
	t.Helper()
	p := filepath.Join(rootfs, "etc", "ssl", "certs", "ca-certificates.crt")
	mustMkdirAll(t, filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, mustCreateTestCertPEM(t), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestApplyRefinesStagedMergedBundle(t *testing.T) {
	rootfs := t.TempDir()
	writeOSRelease(t, rootfs, "ID=debian\n")
	writeStore(t, rootfs)
	ctx, staged := stagedCtx(t, rootfs)

	if err := NewDebian().Apply(ctx); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	b, err := os.ReadFile(filepath.Join(staged, config.MergedCAFileName))
	if err != nil {
		t.Fatalf("staged merged bundle not written: %v", err)
	}
	if n := certs.CountCertificates(b); n != 2 {
		t.Fatalf("staged merged bundle has %d certs, want image root + org CA", n)
	}
}

// An image without a store must not replace the plugin-seeded bundle with an
// org-CA-only one.
func TestApplyKeepsSeedWhenImageHasNoStore(t *testing.T) {
	rootfs := t.TempDir()
	writeOSRelease(t, rootfs, "ID=debian\n")
	ctx, staged := stagedCtx(t, rootfs)

	if err := NewDebian().Apply(ctx); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(staged, config.MergedCAFileName)); !os.IsNotExist(err) {
		t.Fatalf("staged merged bundle should be untouched, stat err = %v", err)
	}
}

func TestApplyFallsBackToStagedBundleOnReadOnlyRootfs(t *testing.T) {
	rootfs := t.TempDir()
	writeOSRelease(t, rootfs, "ID=debian\n")
	writeStore(t, rootfs)
	ctx, _ := stagedCtx(t, rootfs)

	prev := writeRootfsFile
	writeRootfsFile = func(string, string, []byte, os.FileMode) (string, error) {
		return "", &os.PathError{Op: "open", Path: "x", Err: syscall.EROFS}
	}
	t.Cleanup(func() { writeRootfsFile = prev })

	if err := NewDebian().Apply(ctx); err != nil {
		t.Fatalf("Apply() error = %v, want fallback", err)
	}
	if v, _ := ctx.Facts.Get(hookapi.FactTrustStorePath); v != config.ContainerMergedCA {
		t.Fatalf("trust store fact = %q, want %q", v, config.ContainerMergedCA)
	}
	if v, _ := ctx.Facts.Get(hookapi.FactIndividualCAPath); v != config.ContainerOrgCA {
		t.Fatalf("individual CA fact = %q, want %q", v, config.ContainerOrgCA)
	}

	// Without the staged mount there is nothing to fall back to.
	ctx2, _ := stagedCtx(t, rootfs)
	ctx2.ContainerCADir = ""
	if err := NewDebian().Apply(ctx2); err == nil {
		t.Fatal("expected error on read-only rootfs without staged mount")
	}
}
