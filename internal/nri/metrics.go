package nri

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Skip reasons for cainjekt_containers_skipped_total. Keep this set small and
// fixed: labels must not carry pod or namespace names.
const (
	skipNotEnabled     = "not_enabled"
	skipInjectionError = "injection_error"
)

// caRefreshInterval is how often the CA bundle gauges are refreshed from the
// source file even when no container is created, so expiry alerts and a
// rotated ConfigMap are visible on idle nodes.
const caRefreshInterval = time.Minute

// metrics holds the plugin's Prometheus metrics. They live on a private
// registry and are only created in plugin mode; the hook and wrapper never
// touch them.
type metrics struct {
	registry *prometheus.Registry

	injected        prometheus.Counter
	skipped         *prometheus.CounterVec
	injectionErrors prometheus.Counter
	orphansCleaned  prometheus.Counter
	nriConnected    prometheus.Gauge
	nriReconnects   prometheus.Counter

	caCerts       prometheus.Gauge
	caNotAfter    prometheus.Gauge
	caInfo        *prometheus.GaugeVec
	caReadErrors  prometheus.Counter
	caMu          sync.Mutex
	caLastSum     [sha256.Size]byte
	caHaveLastSum bool
}

func newMetrics() *metrics {
	m := &metrics{
		registry: prometheus.NewRegistry(),
		injected: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cainjekt_containers_injected_total",
			Help: "Containers that were set up for CA injection (CA staged, hook and wrapper added).",
		}),
		skipped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cainjekt_containers_skipped_total",
			Help: "Containers started without CA injection, by reason (not_enabled, injection_error).",
		}, []string{"reason"}),
		injectionErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cainjekt_injection_errors_total",
			Help: "Failures to stage the CA bundle for a container, regardless of fail policy.",
		}),
		orphansCleaned: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cainjekt_orphan_dirs_cleaned_total",
			Help: "Staged CA directories removed because their container no longer exists.",
		}),
		nriConnected: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cainjekt_nri_connected",
			Help: "1 while the plugin is connected to and synchronized with the container runtime, 0 otherwise.",
		}),
		nriReconnects: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cainjekt_nri_reconnects_total",
			Help: "Reconnect attempts after the connection to the container runtime was lost or failed.",
		}),
		caCerts: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cainjekt_ca_bundle_certificates",
			Help: "Number of parseable X.509 certificates in the source CA bundle.",
		}),
		caNotAfter: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cainjekt_ca_bundle_earliest_expiry_timestamp_seconds",
			Help: "Unix time of the earliest NotAfter among the CA bundle certificates (0 if none).",
		}),
		caInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cainjekt_ca_bundle_info",
			Help: "Always 1; the sha256 label is the first 12 hex chars of the source CA bundle's SHA-256.",
		}, []string{"sha256"}),
		caReadErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cainjekt_ca_bundle_read_errors_total",
			Help: "Failures to read the source CA bundle during the periodic metrics refresh.",
		}),
	}
	// Initialize the labelled series so they are exported as 0 from the start.
	m.skipped.WithLabelValues(skipNotEnabled)
	m.skipped.WithLabelValues(skipInjectionError)
	m.registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.injected, m.skipped, m.injectionErrors, m.orphansCleaned,
		m.nriConnected, m.nriReconnects,
		m.caCerts, m.caNotAfter, m.caInfo, m.caReadErrors,
	)
	return m
}

// observeCABundle updates the CA bundle gauges from the bundle's content. It
// hashes the content on every call (cheap) and only parses the certificates
// when the hash changed, so it can be called on every staging.
func (m *metrics) observeCABundle(content []byte) {
	sum := sha256.Sum256(content)
	m.caMu.Lock()
	defer m.caMu.Unlock()
	if m.caHaveLastSum && sum == m.caLastSum {
		return
	}
	m.caLastSum, m.caHaveLastSum = sum, true

	count, notAfter := parseCABundle(content)
	m.caCerts.Set(float64(count))
	if notAfter.IsZero() {
		m.caNotAfter.Set(0)
	} else {
		m.caNotAfter.Set(float64(notAfter.Unix()))
	}
	m.caInfo.Reset()
	m.caInfo.WithLabelValues(hex.EncodeToString(sum[:])[:12]).Set(1)
}

// parseCABundle returns the number of parseable certificates in a PEM bundle
// and the earliest NotAfter among them.
func parseCABundle(content []byte) (int, time.Time) {
	var (
		count    int
		earliest time.Time
	)
	for rest := content; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return count, earliest
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		count++
		if earliest.IsZero() || cert.NotAfter.Before(earliest) {
			earliest = cert.NotAfter
		}
	}
}

// refreshCAMetrics re-reads the source CA bundle and updates its gauges. It
// returns the read error, if any.
func (p *Plugin) refreshCAMetrics(sourceCAFile string) error {
	content, err := readSourceCAFile(sourceCAFile)
	if err != nil {
		p.metrics.caReadErrors.Inc()
		return err
	}
	p.metrics.observeCABundle(content)
	return nil
}

// runCAMetricsRefresher keeps the CA bundle gauges current on nodes that
// create no containers for a while. Staging also refreshes them.
func (p *Plugin) runCAMetricsRefresher(ctx context.Context, sourceCAFile string) {
	t := time.NewTicker(caRefreshInterval)
	defer t.Stop()
	failing := false
	for {
		err := p.refreshCAMetrics(sourceCAFile)
		switch {
		case err != nil && !failing:
			p.log.Warn("failed to read CA bundle for metrics", "error", err)
		case err == nil && failing:
			p.log.Info("CA bundle readable again", "ca_file", sourceCAFile)
		}
		failing = err != nil
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
