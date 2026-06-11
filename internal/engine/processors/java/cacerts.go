package java

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/cainjekt/cainjekt/pkg/fsx"
)

const defaultKeystorePassword = "changeit"

// jksMagicBytes are the magic bytes identifying a JKS keystore file.
var jksMagicBytes = []byte{0xFE, 0xED, 0xFE, 0xED}

// jceksMagicBytes are the magic bytes identifying a JCEKS keystore file.
var jceksMagicBytes = []byte{0xCE, 0xCE, 0xCE, 0xCE}

// importIntoCACerts imports PEM-encoded CA certificates into a JKS or PKCS12 cacerts file.
func importIntoCACerts(hostPath string, caPEM []byte) error {
	data, err := os.ReadFile(hostPath)
	if err != nil {
		return fmt.Errorf("failed to read cacerts: %w", err)
	}

	newCerts, err := parseCertsPEM(caPEM)
	if err != nil {
		return fmt.Errorf("failed to parse CA PEM: %w", err)
	}

	var updated []byte
	if isJKS(data) {
		updated, err = importIntoJKS(data, newCerts)
	} else {
		updated, err = importIntoPKCS12(data, newCerts)
	}
	if err != nil {
		return err
	}
	if updated == nil {
		return nil // no new certs to add
	}

	return fsx.AtomicWrite(hostPath, updated, fsx.WriteOptions{
		FallbackMode:  0o644,
		RefuseSymlink: true,
		PreserveOwner: true,
	})
}

func isJKS(data []byte) bool {
	return bytes.HasPrefix(data, jksMagicBytes) || bytes.HasPrefix(data, jceksMagicBytes)
}

func parseCertsPEM(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemData
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}
		rest = r
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}
	return certs, nil
}

func certFingerprint(cert *x509.Certificate) [sha256.Size]byte {
	return sha256.Sum256(cert.Raw)
}

func importIntoPKCS12(data []byte, newCerts []*x509.Certificate) ([]byte, error) {
	existing, err := pkcs12.DecodeTrustStore(data, defaultKeystorePassword)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PKCS12 cacerts: %w", err)
	}

	existingFPs := make(map[[sha256.Size]byte]struct{}, len(existing))
	for _, c := range existing {
		existingFPs[certFingerprint(c)] = struct{}{}
	}

	toAdd := filterNew(newCerts, existingFPs)
	if len(toAdd) == 0 {
		return nil, nil
	}

	all := append(existing, toAdd...)
	updated, err := pkcs12.LegacyRC2.WithRand(rand.Reader).EncodeTrustStore(all, defaultKeystorePassword)
	if err != nil {
		return nil, fmt.Errorf("failed to encode PKCS12 cacerts: %w", err)
	}
	return updated, nil
}

func importIntoJKS(data []byte, newCerts []*x509.Certificate) ([]byte, error) {
	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(data), []byte(defaultKeystorePassword)); err != nil {
		return nil, fmt.Errorf("failed to load JKS cacerts: %w", err)
	}

	existingFPs := make(map[[sha256.Size]byte]struct{})
	for _, alias := range ks.Aliases() {
		entry, err := ks.GetTrustedCertificateEntry(alias)
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(entry.Certificate.Content)
		if err != nil {
			continue
		}
		existingFPs[certFingerprint(cert)] = struct{}{}
	}

	toAdd := filterNew(newCerts, existingFPs)
	if len(toAdd) == 0 {
		return nil, nil
	}

	existingAliases := aliasSet(ks.Aliases())
	for i, cert := range toAdd {
		alias := fmt.Sprintf("cainjekt-%d", i)
		for j := 0; existingAliases[alias]; j++ {
			alias = fmt.Sprintf("cainjekt-%d-%d", i, j)
		}
		existingAliases[alias] = true
		if err := ks.SetTrustedCertificateEntry(alias, keystore.TrustedCertificateEntry{
			CreationTime: time.Now(),
			Certificate: keystore.Certificate{
				Type:    "X.509",
				Content: cert.Raw,
			},
		}); err != nil {
			return nil, fmt.Errorf("failed to add cert to JKS: %w", err)
		}
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(defaultKeystorePassword)); err != nil {
		return nil, fmt.Errorf("failed to store JKS cacerts: %w", err)
	}
	return buf.Bytes(), nil
}

func aliasSet(aliases []string) map[string]bool {
	m := make(map[string]bool, len(aliases))
	for _, a := range aliases {
		m[a] = true
	}
	return m
}

func filterNew(certs []*x509.Certificate, existing map[[sha256.Size]byte]struct{}) []*x509.Certificate {
	var out []*x509.Certificate
	for _, c := range certs {
		fp := certFingerprint(c)
		if _, ok := existing[fp]; !ok {
			out = append(out, c)
			existing[fp] = struct{}{}
		}
	}
	return out
}
