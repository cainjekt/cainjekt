// Package java injects the organization CA into JVM trust stores (cacerts).
package java

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	hookapi "github.com/cainjekt/cainjekt/internal/engine/api"
	"github.com/cainjekt/cainjekt/internal/util/containerfs"
	"github.com/cainjekt/cainjekt/pkg/javakeystore"
)

const (
	processorName        = "lang-java"
	processorPriority    = 100
	aliasPrefix          = "cainjekt-"
	missingContextReason = "missing context"
	javaNotFoundReason   = "no java runtime found"
)

type processor struct{}

// New returns the Java CA injection processor.
func New() hookapi.Processor {
	return &processor{}
}

func (p *processor) Name() string     { return processorName }
func (p *processor) Category() string { return "language" }

func (p *processor) Detect(ctx *hookapi.Context) hookapi.DetectResult {
	if ctx == nil {
		return hookapi.DetectResult{Applicable: false, Priority: processorPriority, Reason: missingContextReason}
	}
	if len(javaHomes(ctx.Rootfs, ctx.Env)) > 0 || len(discoverTrustStores(ctx.Rootfs, ctx.Env)) > 0 {
		return hookapi.DetectResult{Applicable: true, Priority: processorPriority}
	}
	return hookapi.DetectResult{Applicable: false, Priority: processorPriority, Reason: javaNotFoundReason}
}

// Apply adds the organization CA to every cacerts found in the rootfs, the
// equivalent of `keytool -importcert -trustcacerts`. The JVM reads its trust
// store as a JKS or PKCS#12 keystore, so the PEM bundle maintained by the OS
// processors is invisible to it.
//
// Patching in place means the default trust store lookup finds the CA, so no
// JVM flags are needed and an application's own javax.net.ssl.trustStore is
// left alone. Certificates are matched by SHA-256 fingerprint, so re-running
// the hook does not rewrite the store.
//
// Every store is attempted; failures (unparsable store, read-only rootfs, ...)
// are joined into the returned error.
func (p *processor) Apply(ctx *hookapi.Context) error {
	if ctx == nil {
		return nil
	}
	orgCerts, err := readPEMCerts(ctx)
	if err != nil {
		return err
	}
	if len(orgCerts) == 0 {
		return nil
	}

	var errs []error
	for _, store := range discoverTrustStores(ctx.Rootfs, ctx.Env) {
		if err := patchStore(ctx.Rootfs, store, orgCerts); err != nil {
			errs = append(errs, fmt.Errorf("java trust store %s: %w", store, err))
		}
	}
	return errors.Join(errs...)
}

// patchStore adds the missing certificates to the store at the resolved
// container path. It is a no-op when every certificate is already trusted.
func patchStore(rootfs, store string, add []*x509.Certificate) error {
	data, resolved, err := containerfs.ReadFile(rootfs, store)
	if err != nil {
		return fmt.Errorf("failed to read: %w", err)
	}
	merged, err := mergeStore(data, add)
	if err != nil {
		return err
	}
	if merged == nil {
		return nil
	}
	if _, err := containerfs.WriteFile(rootfs, resolved, merged, 0o644); err != nil {
		return fmt.Errorf("failed to write: %w", err)
	}
	return nil
}

// mergeStore returns the re-encoded trust store with the missing certificates
// added, in the store's original format, or nil when they are all trusted
// already.
func mergeStore(data []byte, add []*x509.Certificate) ([]byte, error) {
	format, entries, err := javakeystore.Parse(data)
	if err != nil {
		return nil, err
	}

	present := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		present[fingerprint(e.Cert)] = struct{}{}
	}

	added := 0
	for _, c := range add {
		fp := fingerprint(c)
		if _, ok := present[fp]; ok {
			continue
		}
		present[fp] = struct{}{}
		// Fingerprint-derived alias: stable across runs and unique per CA.
		entries = append(entries, javakeystore.Entry{Alias: aliasPrefix + fp[:16], Cert: c})
		added++
	}
	if added == 0 {
		return nil, nil
	}
	return javakeystore.Encode(format, entries)
}

func readPEMCerts(ctx *hookapi.Context) ([]*x509.Certificate, error) {
	data, err := ctx.ReadCABundle()
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate in %s: %w", ctx.CAFile, err)
		}
		out = append(out, cert)
	}
	return out, nil
}

func fingerprint(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}
