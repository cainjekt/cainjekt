package hookctx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cainjekt/cainjekt/internal/config"
	hookapi "github.com/cainjekt/cainjekt/internal/engine/api"
)

func TestWriteAndRead(t *testing.T) {
	rootfs := t.TempDir()
	t.Setenv(config.EnvHookContextFile, "/etc/cainjekt/test-hook-context.json")

	ctx := &hookapi.Context{
		Mode:        "createruntime",
		Bundle:      "/bundle",
		Annotations: map[string]string{"a": "b"},
		CAFile:      "/etc/cainjekt/ca-bundle.pem",
		FailPolicy:  "fail-open",
		Facts:       hookapi.NewMapFactStore(),
	}
	ctx.Facts.Set(hookapi.FactTrustStorePath, "/etc/ssl/certs/ca-certificates.crt")
	in := NewStateFromContext(ctx, []DetectedProcessor{
		{Name: "dummy-os", Category: "os", Applicable: true, Priority: 20},
		{Name: "dummy-lang", Category: "language", Applicable: true, Priority: 10},
	})
	if err := Write(rootfs, in); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	hostPath := filepath.Join(rootfs, "etc", "cainjekt", "test-hook-context.json")
	if _, err := os.Stat(hostPath); err != nil {
		t.Fatalf("Stat(%q) error = %v", hostPath, err)
	}

	// Read() reads from runtime filesystem path, so re-point it to host-written file for this test.
	t.Setenv(config.EnvHookContextFile, hostPath)
	out, err := Read()
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if out.Context.Facts[string(hookapi.FactTrustStorePath)] != "/etc/ssl/certs/ca-certificates.crt" {
		t.Fatalf("TrustStore mismatch: got=%q", out.Context.Facts[string(hookapi.FactTrustStorePath)])
	}
	if out.Context.FailPolicy != "fail-open" {
		t.Fatalf("FailPolicy mismatch: got=%q", out.Context.FailPolicy)
	}
	raw, err := os.ReadFile(hostPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{`"a"`, "/bundle", "ca-bundle.pem"} {
		if strings.Contains(string(raw), leaked) {
			t.Fatalf("hook context must not persist %s: %s", leaked, raw)
		}
	}
	if len(out.Detected) != 2 {
		t.Fatalf("Detected count mismatch: %#v", out.Detected)
	}
	if out.Detected[0].Category != "os" || out.Detected[1].Category != "language" {
		t.Fatalf("Detected category mismatch: %#v", out.Detected)
	}
}

func TestWriteDoesNotFollowImageSymlinkToHost(t *testing.T) {
	rootfs := t.TempDir()
	hostDir := t.TempDir()
	t.Setenv(config.EnvHookContextFile, config.HookContextFile)
	if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Malicious image: /etc/cainjekt -> <host directory>
	if err := os.Symlink(hostDir, filepath.Join(rootfs, "etc", "cainjekt")); err != nil {
		t.Fatal(err)
	}
	ctx := &hookapi.Context{Facts: hookapi.NewMapFactStore()}
	if err := Write(rootfs, NewStateFromContext(ctx, nil)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(hostDir, filepath.Base(config.HookContextFile))); !os.IsNotExist(err) {
		t.Fatalf("hook context escaped to host directory (stat err = %v)", err)
	}
}
