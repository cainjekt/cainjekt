package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cainjekt/cainjekt/internal/util/containerfs"
)

func WriteExecutableInRootfs(t testing.TB, rootfs, containerPath string) {
	t.Helper()

	hostPath := containerfs.PathInRootfs(rootfs, containerPath)
	if err := os.MkdirAll(filepath.Dir(hostPath), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(hostPath), err)
	}
	if err := os.WriteFile(hostPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(%q): %v", hostPath, err)
	}
}

// SymlinkInRootfs creates a symlink at the given container path inside rootfs.
// The target is written verbatim, so absolute targets point inside the container.
func SymlinkInRootfs(t testing.TB, rootfs, containerPath, target string) {
	t.Helper()

	hostPath := containerfs.PathInRootfs(rootfs, containerPath)
	if err := os.MkdirAll(filepath.Dir(hostPath), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(hostPath), err)
	}
	if err := os.Symlink(target, hostPath); err != nil {
		t.Fatalf("Symlink(%q -> %q): %v", hostPath, target, err)
	}
}

func EnvValue(env []string, key string) string {
	prefix := key + "="
	for _, e := range env {
		if len(e) > len(prefix) && e[:len(prefix)] == prefix {
			return e[len(prefix):]
		}
	}
	return ""
}

// RunIfContainerfsSupported runs the package's tests only where containerfs
// works (Linux 5.6+ with openat2 RESOLVE_IN_ROOT). Use it from TestMain in
// packages whose tests access a container rootfs; elsewhere (e.g. macOS) the
// package is reported as skipped. CI runs on Linux.
func RunIfContainerfsSupported(m *testing.M) {
	if err := containerfs.CheckSupport(); err != nil {
		fmt.Fprintf(os.Stderr, "SKIP: %v\n", err)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// GenerateTestCA creates a self-signed CA certificate for use in tests.
func GenerateTestCA(t testing.TB) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// CertToPEM encodes a certificate as PEM.
func CertToPEM(t testing.TB, cert *x509.Certificate) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// WriteTempCAFile writes PEM data to a temp file and returns its path.
func WriteTempCAFile(t testing.TB, pemData []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "ca-*.pem")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := f.Write(pemData); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()
	return f.Name()
}
