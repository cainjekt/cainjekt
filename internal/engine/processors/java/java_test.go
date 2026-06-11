package java

import (
	"testing"

	hookapi "github.com/cainjekt/cainjekt/internal/engine/api"
	"github.com/cainjekt/cainjekt/internal/testutil"
)

func TestDetectApplicableWhenJavaExists(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	testutil.WriteExecutableInRootfs(t, rootfs, "/usr/bin/java")

	p := New()
	got := p.Detect(&hookapi.Context{Rootfs: rootfs})
	if !got.Applicable {
		t.Fatalf("Detect() should be applicable: %+v", got)
	}
}

func TestDetectNotApplicableWhenJavaDoesNotExist(t *testing.T) {
	t.Parallel()

	p := New()
	got := p.Detect(&hookapi.Context{Rootfs: t.TempDir()})
	if got.Applicable {
		t.Fatalf("Detect() should not be applicable: %+v", got)
	}
}

func TestDetectNotApplicableWhenContextIsNil(t *testing.T) {
	t.Parallel()

	p := New()
	got := p.Detect(nil)
	if got.Applicable {
		t.Fatalf("Detect() should not be applicable: %+v", got)
	}
	if got.Reason != missingContextReason {
		t.Fatalf("Detect() reason mismatch: got=%q want=%q", got.Reason, missingContextReason)
	}
}

func TestApplyNilContextIsNoop(t *testing.T) {
	t.Parallel()

	p := New().(*processor)
	if err := p.Apply(nil); err != nil {
		t.Fatalf("Apply(nil) error = %v", err)
	}
}

func TestApplyNoCACertsIsNoop(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	testutil.WriteExecutableInRootfs(t, rootfs, "/usr/bin/java")

	caFile := testutil.WriteTempCAFile(t, testutil.CertToPEM(t, testutil.GenerateTestCA(t)))
	p := New().(*processor)
	ctx := &hookapi.Context{
		Rootfs: rootfs,
		CAFile: caFile,
		Facts:  hookapi.NewMapFactStore(),
	}
	if err := p.Apply(ctx); err != nil {
		t.Fatalf("Apply() with no cacerts error = %v", err)
	}
}
