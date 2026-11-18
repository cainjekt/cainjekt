package processors

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	hookapi "github.com/cainjekt/cainjekt/internal/engine/api"
	"github.com/cainjekt/cainjekt/internal/util/containerfs"
)

// goCertFiles mirrors the bundle list of Go's crypto/x509 on Linux
// (src/crypto/x509/root_linux.go). Go loads the first file that can be read.
var goCertFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/pki/tls/cacert.pem",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/etc/ssl/cert.pem",
}

// imageLayout is a reduced copy of a real image's trust store layout.
type imageLayout struct {
	osRelease string
	bundle    string            // the only regular trust store file
	symlinks  map[string]string // link -> target, as found in the image
	// openSSLCertFile is OpenSSL's compiled-in default CA file
	// (X509_get_default_cert_file), which Ruby's openssl and .NET read when
	// SSL_CERT_FILE is unset. Empty for images without OpenSSL.
	openSSLCertFile string
}

// runtimeDefaultLayouts were taken from the images named in each key. They
// pin the reason cainjekt has no Go, Ruby or .NET processor: on a writable
// rootfs the OS processors already patch the file these runtimes read.
var runtimeDefaultLayouts = map[string]imageLayout{
	// ruby:3.3-slim, mcr.microsoft.com/dotnet/runtime:8.0
	"debian": {
		osRelease: "ID=debian\n",
		bundle:    "/etc/ssl/certs/ca-certificates.crt",
		symlinks: map[string]string{
			"/usr/lib/ssl/cert.pem": "/etc/ssl/certs/ca-certificates.crt",
			"/usr/lib/ssl/certs":    "/etc/ssl/certs",
		},
		openSSLCertFile: "/usr/lib/ssl/cert.pem",
	},
	// mcr.microsoft.com/dotnet/runtime:8.0-noble-chiseled
	"ubuntu-chiseled": {
		bundle: "/etc/ssl/certs/ca-certificates.crt",
		symlinks: map[string]string{
			"/etc/os-release":       "../usr/lib/os-release",
			"/usr/lib/ssl/cert.pem": "/etc/ssl/certs/ca-certificates.crt",
		},
		openSSLCertFile: "/usr/lib/ssl/cert.pem",
	},
	// ruby:3.3-alpine, mcr.microsoft.com/dotnet/runtime:8.0-alpine
	"alpine": {
		osRelease: "ID=alpine\n",
		bundle:    "/etc/ssl/certs/ca-certificates.crt",
		symlinks: map[string]string{
			"/etc/ssl/cert.pem": "certs/ca-certificates.crt",
		},
		openSSLCertFile: "/etc/ssl/cert.pem",
	},
	// registry.access.redhat.com/ubi9/ruby-33
	"rhel": {
		osRelease: "ID=\"rhel\"\nID_LIKE=\"fedora\"\n",
		bundle:    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
		symlinks: map[string]string{
			"/etc/pki/tls/certs/ca-bundle.crt": "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
			"/etc/pki/tls/cert.pem":            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
			"/etc/ssl/cert.pem":                "/etc/pki/tls/cert.pem",
			"/etc/ssl/certs":                   "/etc/pki/tls/certs",
		},
		openSSLCertFile: "/etc/pki/tls/cert.pem",
	},
	// mcr.microsoft.com/dotnet/runtime:8.0-azurelinux3.0 (ID not matched by
	// any distro processor, handled by os-fallback)
	"azurelinux": {
		osRelease: "ID=azurelinux\n",
		bundle:    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
		symlinks: map[string]string{
			"/etc/ssl/certs/ca-certificates.crt": "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
			"/etc/pki/tls/certs/ca-bundle.crt":   "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
			"/etc/pki/tls/cert.pem":              "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
			"/usr/lib/ssl/certs":                 "/etc/pki/tls/certs",
		},
		openSSLCertFile: "/etc/pki/tls/cert.pem",
	},
	// registry.suse.com/bci/ruby (Ruby reports DEFAULT_CERT_FILE as below)
	"suse": {
		osRelease: "ID=\"sles\"\nID_LIKE=\"suse\"\n",
		bundle:    "/var/lib/ca-certificates/ca-bundle.pem",
		symlinks: map[string]string{
			"/etc/ssl/ca-bundle.pem": "/var/lib/ca-certificates/ca-bundle.pem",
		},
		openSSLCertFile: "/var/lib/ca-certificates/ca-bundle.pem",
	},
	// FROM scratch with a static Go binary: no os-release, no trust store.
	"scratch": {},
}

func TestOSProcessorsCoverGoAndOpenSSLDefaults(t *testing.T) {
	t.Parallel()

	ca, leaf := testCAAndLeaf(t)
	for name, layout := range runtimeDefaultLayouts {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rootfs := t.TempDir()
			buildLayout(t, rootfs, layout)
			runOSProcessors(t, rootfs, ca)

			assertTrusted(t, rootfs, "go", goDefaultBundle(t, rootfs), leaf)
			if layout.openSSLCertFile != "" {
				assertTrusted(t, rootfs, "openssl", layout.openSSLCertFile, leaf)
			}
		})
	}
}

// TestOSProcessorsGoDefaultWithHostSymlink covers an image whose trust store
// directory is an absolute symlink that would point at the node's own store
// if followed on the host. The bundle must be written inside the rootfs, where
// the container's Go runtime will read it, and the host file left untouched.
func TestOSProcessorsGoDefaultWithHostSymlink(t *testing.T) {
	t.Parallel()

	ca, leaf := testCAAndLeaf(t)
	tmp := t.TempDir()
	rootfs := filepath.Join(tmp, "rootfs")
	hostCerts := filepath.Join(tmp, "host", "etc", "ssl", "certs")
	hostBundle := filepath.Join(hostCerts, "ca-certificates.crt")
	mkdirAll(t, hostCerts)
	writeFile(t, hostBundle, []byte("host bundle\n"))

	mkdirAll(t, filepath.Join(rootfs, "etc", "ssl"))
	writeFile(t, filepath.Join(rootfs, "etc", "os-release"), []byte("ID=debian\n"))
	if err := os.Symlink(hostCerts, filepath.Join(rootfs, "etc", "ssl", "certs")); err != nil {
		t.Fatal(err)
	}

	runOSProcessors(t, rootfs, ca)

	if got, err := os.ReadFile(hostBundle); err != nil || string(got) != "host bundle\n" {
		t.Fatalf("host bundle was modified: %q, %v", got, err)
	}
	assertTrusted(t, rootfs, "go", goDefaultBundle(t, rootfs), leaf)
}

func buildLayout(t *testing.T, rootfs string, l imageLayout) {
	t.Helper()
	if l.osRelease != "" {
		writeInRootfs(t, rootfs, "/etc/os-release", []byte(l.osRelease))
	}
	if _, ok := l.symlinks["/etc/os-release"]; ok {
		writeInRootfs(t, rootfs, "/usr/lib/os-release", []byte("ID=ubuntu\nID_LIKE=debian\n"))
	}
	if l.bundle != "" {
		writeInRootfs(t, rootfs, l.bundle, []byte("# distro bundle\n"))
	}
	for link, target := range l.symlinks {
		host := containerfs.PathInRootfs(rootfs, link)
		mkdirAll(t, filepath.Dir(host))
		if err := os.Symlink(target, host); err != nil {
			t.Fatal(err)
		}
	}
}

// runOSProcessors runs the registered OS processors the way the hook runner
// does: in priority order, every applicable one.
func runOSProcessors(t *testing.T, rootfs string, caPEM []byte) {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	writeFile(t, caFile, caPEM)

	ctx := &hookapi.Context{Rootfs: rootfs, CAFile: caFile, Facts: hookapi.NewMapFactStore()}
	var osProcs []hookapi.Processor
	for _, p := range Default() {
		if p.Category() == "os" {
			osProcs = append(osProcs, p)
		}
	}
	for _, d := range DetectSorted(ctx, osProcs) {
		if !d.Detect.Applicable {
			continue
		}
		if err := d.Processor.Apply(ctx); err != nil {
			t.Fatalf("%s: Apply() error = %v", d.Processor.Name(), err)
		}
	}
	if v, ok := ctx.Facts.Get(hookapi.FactTrustStorePath); !ok || v == "" {
		t.Fatalf("no OS processor set %s", hookapi.FactTrustStorePath)
	}
}

func goDefaultBundle(t *testing.T, rootfs string) string {
	t.Helper()
	for _, f := range goCertFiles {
		if _, _, err := containerfs.ReadFile(rootfs, f); err == nil {
			return f
		}
	}
	t.Fatal("no Go default bundle in rootfs")
	return ""
}

func assertTrusted(t *testing.T, rootfs, runtime, bundle string, leaf *x509.Certificate) {
	t.Helper()
	data, _, err := containerfs.ReadFile(rootfs, bundle)
	if err != nil {
		t.Fatalf("%s: read %s: %v", runtime, bundle, err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(data)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("%s: org CA not trusted via %s: %v", runtime, bundle, err)
	}
}

func testCAAndLeaf(t *testing.T) ([]byte, *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cainjekt test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), leaf
}

func writeInRootfs(t *testing.T, rootfs, containerPath string, data []byte) {
	t.Helper()
	host := containerfs.PathInRootfs(rootfs, containerPath)
	mkdirAll(t, filepath.Dir(host))
	writeFile(t, host, data)
}

func mkdirAll(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, p string, data []byte) {
	t.Helper()
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
