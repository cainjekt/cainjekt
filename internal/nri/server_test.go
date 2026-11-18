package nri

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

func TestHTTPHandlers(t *testing.T) {
	t.Parallel()
	m := newMetrics()
	var ready atomic.Bool
	srv := newHTTPServer(m.registry, ready.Load)
	if srv.ReadHeaderTimeout <= 0 {
		t.Fatal("ReadHeaderTimeout not set")
	}

	if code, _ := get(t, srv.Handler, "/healthz"); code != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200", code)
	}
	if code, _ := get(t, srv.Handler, "/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz before sync = %d, want 503", code)
	}
	ready.Store(true)
	if code, _ := get(t, srv.Handler, "/readyz"); code != http.StatusOK {
		t.Fatalf("/readyz after sync = %d, want 200", code)
	}

	m.injected.Inc()
	code, body := get(t, srv.Handler, "/metrics")
	if code != http.StatusOK {
		t.Fatalf("/metrics = %d", code)
	}
	for _, want := range []string{
		"cainjekt_containers_injected_total 1",
		`cainjekt_containers_skipped_total{reason="not_enabled"} 0`,
		"cainjekt_nri_connected 0",
		"go_goroutines",
		"process_",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics lacks %q", want)
		}
	}
}

func TestServeHTTPShutsDownWithContext(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveHTTP(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)),
			newHTTPServer(newMetrics().registry, func() bool { return true }), ln)
	}()

	resp, err := http.Get("http://" + ln.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz = %d", resp.StatusCode)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(httpShutdownTimeout + time.Second):
		t.Fatal("server did not shut down after context cancel")
	}
}
