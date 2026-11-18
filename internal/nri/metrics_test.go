package nri

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cainjekt/cainjekt/internal/config"
	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func testPEMCert(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    notAfter.Add(-24 * time.Hour),
		NotAfter:     notAfter,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func shortHash(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])[:12]
}

func TestObserveCABundle(t *testing.T) {
	t.Parallel()
	m := newMetrics()
	early := time.Unix(2000000000, 0)
	late := time.Unix(2100000000, 0)
	bundle := append(testPEMCert(t, late), testPEMCert(t, early)...)
	bundle = append(bundle, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")...) // unparseable

	m.observeCABundle(bundle)
	if got := testutil.ToFloat64(m.caCerts); got != 2 {
		t.Fatalf("certificates = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.caNotAfter); got != float64(early.Unix()) {
		t.Fatalf("earliest expiry = %v, want %v", got, early.Unix())
	}
	if got := testutil.ToFloat64(m.caInfo.WithLabelValues(shortHash(bundle))); got != 1 {
		t.Fatalf("info{sha256=%s} = %v, want 1", shortHash(bundle), got)
	}

	// A rotated bundle replaces the info series instead of adding one.
	rotated := testPEMCert(t, late)
	m.observeCABundle(rotated)
	if n := testutil.CollectAndCount(m.caInfo); n != 1 {
		t.Fatalf("info series = %d, want 1", n)
	}
	if got := testutil.ToFloat64(m.caInfo.WithLabelValues(shortHash(rotated))); got != 1 {
		t.Fatal("info series not updated to the rotated hash")
	}
	if got := testutil.ToFloat64(m.caNotAfter); got != float64(late.Unix()) {
		t.Fatalf("earliest expiry after rotation = %v", got)
	}

	m.observeCABundle([]byte("garbage"))
	if testutil.ToFloat64(m.caCerts) != 0 || testutil.ToFloat64(m.caNotAfter) != 0 {
		t.Fatal("gauges not reset for a bundle without certificates")
	}
}

func TestRefreshCAMetrics(t *testing.T) {
	t.Parallel()
	p := newPlugin(nil)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := p.refreshCAMetrics(path); err == nil {
		t.Fatal("want error for missing CA file")
	}
	if got := testutil.ToFloat64(p.metrics.caReadErrors); got != 1 {
		t.Fatalf("read errors = %v, want 1", got)
	}
	if err := os.WriteFile(path, testPEMCert(t, time.Now().Add(time.Hour)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.refreshCAMetrics(path); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(p.metrics.caCerts); got != 1 {
		t.Fatalf("certificates = %v, want 1", got)
	}
}

func TestCreateContainerMetrics(t *testing.T) {
	t.Setenv(config.EnvCAFile, writeTempSourceCA(t))
	t.Setenv(config.EnvDynamicCARoot, t.TempDir())
	p := newPlugin(nil)
	enabled := &api.PodSandbox{Annotations: map[string]string{config.AnnoEnabled: "true"}}

	if _, _, err := p.CreateContainer(context.Background(), &api.PodSandbox{}, &api.Container{Id: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.CreateContainer(context.Background(), enabled, &api.Container{Id: "b", Args: []string{"sh"}}); err != nil {
		t.Fatal(err)
	}
	// Staging fails (missing source) under fail-open: error and skip.
	t.Setenv(config.EnvCAFile, filepath.Join(t.TempDir(), "missing.pem"))
	if _, _, err := p.CreateContainer(context.Background(), enabled, &api.Container{Id: "c"}); err != nil {
		t.Fatal(err)
	}
	// Under fail-closed the container fails instead: error but no skip.
	p.failPolicy = config.FailPolicyClosed
	if _, _, err := p.CreateContainer(context.Background(), enabled, &api.Container{Id: "d"}); err == nil {
		t.Fatal("want error under fail-closed")
	}

	m := p.metrics
	for name, c := range map[string]struct{ got, want float64 }{
		"injected":                {testutil.ToFloat64(m.injected), 1},
		"skipped{not_enabled}":    {testutil.ToFloat64(m.skipped.WithLabelValues(skipNotEnabled)), 1},
		"skipped{injection_err}":  {testutil.ToFloat64(m.skipped.WithLabelValues(skipInjectionError)), 1},
		"injection_errors":        {testutil.ToFloat64(m.injectionErrors), 2},
		"ca_bundle_info (staged)": {float64(testutil.CollectAndCount(m.caInfo)), 1},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", name, c.got, c.want)
		}
	}
}

func TestSweepOrphansCountsRemovals(t *testing.T) {
	root := t.TempDir()
	t.Setenv(config.EnvDynamicCARoot, root)
	p := newPlugin(nil)
	mkStaged(t, root, "gone1", time.Hour)
	mkStaged(t, root, "gone2", time.Hour)
	if n := p.sweepOrphans(time.Now()); n != 2 {
		t.Fatalf("removed %d, want 2", n)
	}
	if got := testutil.ToFloat64(p.metrics.orphansCleaned); got != 2 {
		t.Fatalf("orphans cleaned = %v, want 2", got)
	}
}

// syncStub synchronizes the plugin on each Run, then holds the connection
// until drop is signalled (or ctx is cancelled).
type syncStub struct {
	stub.Stub
	p      *Plugin
	synced chan struct{}
	drop   chan struct{}
}

func (s *syncStub) Run(ctx context.Context) error {
	if _, err := s.p.Synchronize(ctx, nil, nil); err != nil {
		return err
	}
	s.synced <- struct{}{}
	select {
	case <-s.drop:
		return errors.New("connection closed")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestReadinessFollowsConnection(t *testing.T) {
	t.Setenv(config.EnvDynamicCARoot, t.TempDir())
	p := newPlugin(slog.New(slog.NewTextHandler(io.Discard, nil)))
	s := &syncStub{p: p, synced: make(chan struct{}), drop: make(chan struct{})}
	p.stub = s

	if p.ready.Load() {
		t.Fatal("ready before connecting")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.runNRI(ctx) }()

	<-s.synced
	if !p.ready.Load() || testutil.ToFloat64(p.metrics.nriConnected) != 1 {
		t.Fatal("not ready after Synchronize")
	}

	s.drop <- struct{}{}
	<-s.synced // reconnected and synchronized again
	if got := testutil.ToFloat64(p.metrics.nriReconnects); got != 1 {
		t.Fatalf("reconnects = %v, want 1", got)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if p.ready.Load() || testutil.ToFloat64(p.metrics.nriConnected) != 0 {
		t.Fatal("still ready after the connection ended")
	}
}

func TestReadinessDropsWhenRunReturns(t *testing.T) {
	t.Setenv(config.EnvDynamicCARoot, t.TempDir())
	p := newPlugin(nil)
	// As if a previous connection had synchronized; the next Run fails
	// without synchronizing, so ready must be cleared by runNRI itself.
	p.setReady(true)
	p.stub = &fakeStub{fails: 1}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.runNRI(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for p.ready.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if p.ready.Load() {
		t.Fatal("ready not cleared after Run returned")
	}
	cancel()
	<-done
}
