package java

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/cainjekt/cainjekt/internal/testutil"
)

func buildPKCS12TrustStore(certs []*x509.Certificate) ([]byte, error) {
	return pkcs12.LegacyRC2.WithRand(rand.Reader).EncodeTrustStore(certs, defaultKeystorePassword)
}

func decodePKCS12TrustStore(data []byte) ([]*x509.Certificate, error) {
	return pkcs12.DecodeTrustStore(data, defaultKeystorePassword)
}

func buildJKSTrustStore(certs []*x509.Certificate) ([]byte, error) {
	ks := keystore.New()
	for i, cert := range certs {
		alias := fmt.Sprintf("test-%d", i)
		if err := ks.SetTrustedCertificateEntry(alias, keystore.TrustedCertificateEntry{
			CreationTime: time.Now(),
			Certificate: keystore.Certificate{
				Type:    "X.509",
				Content: cert.Raw,
			},
		}); err != nil {
			return nil, err
		}
	}
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(defaultKeystorePassword)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeJKSTrustStore(data []byte) ([]*x509.Certificate, error) {
	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(data), []byte(defaultKeystorePassword)); err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for _, alias := range ks.Aliases() {
		entry, err := ks.GetTrustedCertificateEntry(alias)
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(entry.Certificate.Content)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func TestImportIntoPKCS12(t *testing.T) {
	t.Parallel()

	ca1 := testutil.GenerateTestCA(t)
	ca2 := testutil.GenerateTestCA(t)

	// Build initial PKCS12 trust store containing ca1.
	initial, err := buildPKCS12TrustStore([]*x509.Certificate{ca1})
	if err != nil {
		t.Fatalf("buildPKCS12TrustStore: %v", err)
	}

	hostPath := filepath.Join(t.TempDir(), "cacerts")
	if err := os.WriteFile(hostPath, initial, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	caPEM := testutil.CertToPEM(t, ca2)
	if err := importIntoCACerts(hostPath, caPEM); err != nil {
		t.Fatalf("importIntoCACerts: %v", err)
	}

	updated, err := os.ReadFile(hostPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	certs, err := decodePKCS12TrustStore(updated)
	if err != nil {
		t.Fatalf("decodePKCS12TrustStore: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}
}

func TestImportIntoPKCS12Idempotent(t *testing.T) {
	t.Parallel()

	ca := testutil.GenerateTestCA(t)

	initial, err := buildPKCS12TrustStore([]*x509.Certificate{ca})
	if err != nil {
		t.Fatalf("buildPKCS12TrustStore: %v", err)
	}

	hostPath := filepath.Join(t.TempDir(), "cacerts")
	if err := os.WriteFile(hostPath, initial, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	stat1, _ := os.Stat(hostPath)

	caPEM := testutil.CertToPEM(t, ca)
	if err := importIntoCACerts(hostPath, caPEM); err != nil {
		t.Fatalf("importIntoCACerts: %v", err)
	}

	stat2, _ := os.Stat(hostPath)
	if stat1.ModTime() != stat2.ModTime() {
		t.Fatal("cacerts file was modified even though cert was already present")
	}
}

func TestImportIntoJKS(t *testing.T) {
	t.Parallel()

	ca1 := testutil.GenerateTestCA(t)
	ca2 := testutil.GenerateTestCA(t)

	initial, err := buildJKSTrustStore([]*x509.Certificate{ca1})
	if err != nil {
		t.Fatalf("buildJKSTrustStore: %v", err)
	}

	hostPath := filepath.Join(t.TempDir(), "cacerts")
	if err := os.WriteFile(hostPath, initial, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	caPEM := testutil.CertToPEM(t, ca2)
	if err := importIntoCACerts(hostPath, caPEM); err != nil {
		t.Fatalf("importIntoCACerts: %v", err)
	}

	updated, err := os.ReadFile(hostPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	certs, err := decodeJKSTrustStore(updated)
	if err != nil {
		t.Fatalf("decodeJKSTrustStore: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}
}

func TestImportIntoJKSIdempotent(t *testing.T) {
	t.Parallel()

	ca := testutil.GenerateTestCA(t)

	initial, err := buildJKSTrustStore([]*x509.Certificate{ca})
	if err != nil {
		t.Fatalf("buildJKSTrustStore: %v", err)
	}

	hostPath := filepath.Join(t.TempDir(), "cacerts")
	if err := os.WriteFile(hostPath, initial, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	stat1, _ := os.Stat(hostPath)

	caPEM := testutil.CertToPEM(t, ca)
	if err := importIntoCACerts(hostPath, caPEM); err != nil {
		t.Fatalf("importIntoCACerts: %v", err)
	}

	stat2, _ := os.Stat(hostPath)
	if stat1.ModTime() != stat2.ModTime() {
		t.Fatal("cacerts file was modified even though cert was already present")
	}
}

func TestIsJKS(t *testing.T) {
	t.Parallel()

	jks, err := buildJKSTrustStore(nil)
	if err != nil {
		t.Fatalf("buildJKSTrustStore: %v", err)
	}
	if !isJKS(jks) {
		t.Fatal("expected isJKS to return true for JKS data")
	}

	p12, err := buildPKCS12TrustStore(nil)
	if err != nil {
		t.Fatalf("buildPKCS12TrustStore: %v", err)
	}
	if isJKS(p12) {
		t.Fatal("expected isJKS to return false for PKCS12 data")
	}
}
