package nri

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	defaultHTTPAddr       = ":9102"
	httpReadHeaderTimeout = 5 * time.Second
	httpShutdownTimeout   = 5 * time.Second
)

// newHTTPServer serves:
//   - GET /healthz: 200 while the process is alive.
//   - GET /readyz:  200 while connected to and synchronized with the runtime, 503 otherwise.
//   - GET /metrics: the plugin's private Prometheus registry.
//
// Based on the health/metrics server in natrontech/cainjekt.
func newHTTPServer(reg *prometheus.Registry, ready func() bool) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "not ready: not synchronized with the container runtime\n")
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	return &http.Server{Handler: mux, ReadHeaderTimeout: httpReadHeaderTimeout}
}

// serveHTTP serves srv on ln until ctx is cancelled, then shuts it down
// gracefully. It returns once the shutdown has completed.
func serveHTTP(ctx context.Context, log *slog.Logger, srv *http.Server, ln net.Listener) {
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			log.Warn("HTTP server shutdown", "error", err)
		}
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("HTTP server failed", "error", err)
	}
	<-shutdownDone
}
