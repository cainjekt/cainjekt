package java

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	hookapi "github.com/cainjekt/cainjekt/internal/engine/api"
	"github.com/cainjekt/cainjekt/internal/testutil"
	"github.com/cainjekt/cainjekt/internal/util/containerfs"
	"github.com/cainjekt/cainjekt/pkg/javakeystore"
)

const (
	jvmHome = "/usr/lib/jvm/java-17-openjdk"
	orgCN   = "cainjekt-test-ca"
)

func TestDetectApplicableWhenJavaExists(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	testutil.WriteExecutableInRootfs(t, rootfs, "/usr/bin/java")

	got := New().Detect(&hookapi.Context{Rootfs: rootfs})
	if !got.Applicable {
		t.Fatalf("Detect() should be applicable: %+v", got)
	}
}

func TestDetectApplicableWhenJavaIsAbsoluteSymlinkChain(t *testing.T) {
	t.Parallel()

	// RHEL alternatives layout: /usr/bin/java -> /etc/alternatives/java -> real
	// binary, all absolute symlinks. Resolution must stay inside the rootfs.
	rootfs := t.TempDir()
	testutil.WriteExecutableInRootfs(t, rootfs, jvmHome+"/bin/java")
	testutil.SymlinkInRootfs(t, rootfs, "/etc/alternatives/java", jvmHome+"/bin/java")
	testutil.SymlinkInRootfs(t, rootfs, "/usr/bin/java", "/etc/alternatives/java")

	got := New().Detect(&hookapi.Context{Rootfs: rootfs})
	if !got.Applicable {
		t.Fatalf("Detect() should be applicable: %+v", got)
	}
	homes := javaHomes(rootfs, nil)
	if len(homes) == 0 || homes[0] != jvmHome {
		t.Fatalf("javaHomes() = %v, want %s first", homes, jvmHome)
	}
}

// jlink runtimes put the launcher somewhere only JAVA_HOME knows about.
func TestDetectApplicableFromJavaHomeEnv(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	writeTrustStore(t, rootfs, "/app/runtime/lib/security/cacerts", javakeystore.FormatJKS)

	got := New().Detect(&hookapi.Context{Rootfs: rootfs, Env: []string{"JAVA_HOME=/app/runtime"}})
	if !got.Applicable {
		t.Fatalf("Detect() should be applicable: %+v", got)
	}
}

func TestDetectNotApplicableWhenJavaDoesNotExist(t *testing.T) {
	t.Parallel()

	got := New().Detect(&hookapi.Context{Rootfs: t.TempDir()})
	if got.Applicable {
		t.Fatalf("Detect() should not be applicable: %+v", got)
	}
	if got.Reason != javaNotFoundReason {
		t.Fatalf("Detect() reason mismatch: got=%q want=%q", got.Reason, javaNotFoundReason)
	}
}

func TestDetectNotApplicableWhenContextIsNil(t *testing.T) {
	t.Parallel()

	got := New().Detect(nil)
	if got.Applicable {
		t.Fatalf("Detect() should not be applicable: %+v", got)
	}
	if got.Reason != missingContextReason {
		t.Fatalf("Detect() reason mismatch: got=%q want=%q", got.Reason, missingContextReason)
	}
}

func TestApplyNilContextIsNoop(t *testing.T) {
	t.Parallel()

	if err := New().Apply(nil); err != nil {
		t.Fatalf("Apply(nil) error = %v", err)
	}
}

func TestApplyNoCACertsIsNoop(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	testutil.WriteExecutableInRootfs(t, rootfs, "/usr/bin/java")

	if err := New().Apply(newContext(t, rootfs)); err != nil {
		t.Fatalf("Apply() with no cacerts error = %v", err)
	}
}

func TestApplyAddsCAToCacerts(t *testing.T) {
	t.Parallel()

	for _, format := range []javakeystore.Format{javakeystore.FormatJKS, javakeystore.FormatPKCS12} {
		t.Run(format.String(), func(t *testing.T) {
			t.Parallel()

			rootfs := t.TempDir()
			store := jvmHome + "/lib/security/cacerts"
			testutil.WriteExecutableInRootfs(t, rootfs, jvmHome+"/bin/java")
			testutil.SymlinkInRootfs(t, rootfs, "/usr/bin/java", jvmHome+"/bin/java")
			writeTrustStore(t, rootfs, store, format)

			if err := New().Apply(newContext(t, rootfs)); err != nil {
				t.Fatalf("Apply() error = %v", err)
			}

			gotFormat, entries := readTrustStore(t, containerfs.PathInRootfs(rootfs, store))
			if gotFormat != format {
				t.Fatalf("Apply() changed keystore format: got=%s want=%s", gotFormat, format)
			}
			if len(entries) != 2 {
				t.Fatalf("Apply() wrote %d entries, want 2 (existing root + org CA)", len(entries))
			}
			if !hasCommonName(entries, orgCN) || !hasCommonName(entries, "existing-root") {
				t.Fatalf("Apply() lost or missed a certificate: %v", aliases(entries))
			}
		})
	}
}

// Stores found through the glob list (no launcher on a known path) are patched.
func TestApplyPatchesGlobDiscoveredStores(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	stores := []string{
		"/opt/java/openjdk/jre/lib/security/cacerts",
		"/usr/local/openjdk-17/lib/security/cacerts",
		"/opt/jdk-21/lib/security/cacerts",
	}
	for _, s := range stores {
		writeTrustStore(t, rootfs, s, javakeystore.FormatPKCS12)
	}

	if err := New().Apply(newContext(t, rootfs)); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, s := range stores {
		_, entries := readTrustStore(t, containerfs.PathInRootfs(rootfs, s))
		if !hasCommonName(entries, orgCN) {
			t.Fatalf("Apply() did not patch %s: %v", s, aliases(entries))
		}
	}
}

// The JDK's cacerts is normally a symlink into the distro trust store; the
// hook must patch the target, not replace the link.
func TestApplyFollowsCacertsSymlinkToDistroStore(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	testutil.WriteExecutableInRootfs(t, rootfs, "/usr/bin/java")
	writeTrustStore(t, rootfs, "/etc/pki/ca-trust/extracted/java/cacerts", javakeystore.FormatJKS)
	testutil.SymlinkInRootfs(t, rootfs, "/etc/pki/java/cacerts", "/etc/pki/ca-trust/extracted/java/cacerts")
	testutil.SymlinkInRootfs(t, rootfs, jvmHome+"/lib/security/cacerts", "/etc/pki/java/cacerts")

	if err := New().Apply(newContext(t, rootfs)); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	for _, link := range []string{"/etc/pki/java/cacerts", jvmHome + "/lib/security/cacerts"} {
		host := containerfs.PathInRootfs(rootfs, link)
		if fi, err := os.Lstat(host); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("Apply() replaced the symlink %s: err=%v", link, err)
		}
	}
	_, entries := readTrustStore(t, containerfs.PathInRootfs(rootfs, "/etc/pki/ca-trust/extracted/java/cacerts"))
	if !hasCommonName(entries, orgCN) {
		t.Fatalf("Apply() did not patch the symlink target: %v", aliases(entries))
	}
	if len(entries) != 2 {
		t.Fatalf("Apply() wrote %d entries, want 2 (the store must be patched once)", len(entries))
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	store := jvmHome + "/lib/security/cacerts"
	testutil.WriteExecutableInRootfs(t, rootfs, "/usr/bin/java")
	writeTrustStore(t, rootfs, store, javakeystore.FormatJKS)
	hostStore := containerfs.PathInRootfs(rootfs, store)

	ctx := newContext(t, rootfs)
	if err := New().Apply(ctx); err != nil {
		t.Fatalf("first Apply() error = %v", err)
	}
	first := mustReadFile(t, hostStore)

	if err := New().Apply(ctx); err != nil {
		t.Fatalf("second Apply() error = %v", err)
	}
	if !bytes.Equal(first, mustReadFile(t, hostStore)) {
		t.Fatal("Apply() rewrote the trust store on a second run")
	}
}

// A CA that is already trusted under a different alias is detected by
// fingerprint and the store is left untouched.
func TestApplySkipsCAAlreadyTrustedUnderOtherAlias(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	store := "/etc/ssl/certs/java/cacerts"
	ca := newTestCert(t, orgCN)
	data, err := javakeystore.Encode(javakeystore.FormatJKS, []javakeystore.Entry{{Alias: "corp-root", Cert: ca}})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	writeRootfsFile(t, rootfs, store, data)

	ctx := &hookapi.Context{Rootfs: rootfs, CAFile: testutil.WriteTempCAFile(t, testutil.CertToPEM(t, ca)), Facts: hookapi.NewMapFactStore()}
	if err := New().Apply(ctx); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !bytes.Equal(data, mustReadFile(t, containerfs.PathInRootfs(rootfs, store))) {
		t.Fatal("Apply() rewrote a store that already trusts the CA")
	}
}

// A broken store is reported, but does not stop the other stores from being
// patched.
func TestApplyReportsUnparsableStoreAndPatchesOthers(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	good := "/etc/ssl/certs/java/cacerts"
	bad := "/etc/pki/java/cacerts"
	writeTrustStore(t, rootfs, good, javakeystore.FormatJKS)
	writeRootfsFile(t, rootfs, bad, []byte("not a keystore"))

	err := New().Apply(newContext(t, rootfs))
	if err == nil {
		t.Fatal("Apply() should report the unparsable store")
	}
	_, entries := readTrustStore(t, containerfs.PathInRootfs(rootfs, good))
	if !hasCommonName(entries, orgCN) {
		t.Fatalf("Apply() did not patch the healthy store: %v", aliases(entries))
	}
	if got := mustReadFile(t, containerfs.PathInRootfs(rootfs, bad)); string(got) != "not a keystore" {
		t.Fatalf("Apply() modified the unparsable store: %q", got)
	}
}

// Read-only rootfs handling is out of scope; Apply must fail cleanly.
func TestApplyReturnsErrorWhenStoreIsNotWritable(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}

	rootfs := t.TempDir()
	store := jvmHome + "/lib/security/cacerts"
	testutil.WriteExecutableInRootfs(t, rootfs, "/usr/bin/java")
	writeTrustStore(t, rootfs, store, javakeystore.FormatJKS)
	hostStore := containerfs.PathInRootfs(rootfs, store)
	before := mustReadFile(t, hostStore)

	securityDir := filepath.Dir(hostStore)
	if err := os.Chmod(securityDir, 0o555); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(securityDir, 0o755) })

	if err := New().Apply(newContext(t, rootfs)); err == nil {
		t.Fatal("Apply() should fail when cacerts cannot be written")
	}
	if !bytes.Equal(before, mustReadFile(t, hostStore)) {
		t.Fatal("Apply() changed the store despite failing")
	}
}

// The image is untrusted and the hook runs as root on the host: cacerts (and
// everything leading to it) that point at host paths must be resolved inside
// the rootfs, never read or written on the host.
func TestApplyNeverTouchesHostThroughSymlinks(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		setup        func(t *testing.T, rootfs, hostDir string)
		hostJavaHome bool // set JAVA_HOME to the host JDK path
	}{
		{
			name: "absolute cacerts symlink",
			setup: func(t *testing.T, rootfs, hostDir string) {
				testutil.WriteExecutableInRootfs(t, rootfs, "/usr/bin/java")
				testutil.SymlinkInRootfs(t, rootfs, "/usr/lib/jvm/jdk/lib/security/cacerts", filepath.Join(hostDir, "cacerts"))
				testutil.SymlinkInRootfs(t, rootfs, "/etc/ssl/certs/java/cacerts", filepath.Join(hostDir, "cacerts"))
			},
		},
		{
			name: "relative cacerts symlink climbing out",
			setup: func(t *testing.T, rootfs, hostDir string) {
				rel, err := filepath.Rel(containerfs.PathInRootfs(rootfs, "/etc/pki/java"), filepath.Join(hostDir, "cacerts"))
				if err != nil {
					t.Fatalf("Rel() error = %v", err)
				}
				testutil.SymlinkInRootfs(t, rootfs, "/etc/pki/java/cacerts", rel)
			},
		},
		{
			name: "JDK directory symlinked to host",
			setup: func(t *testing.T, rootfs, hostDir string) {
				testutil.SymlinkInRootfs(t, rootfs, "/usr/lib/jvm/evil", filepath.Dir(filepath.Dir(hostDir)))
				testutil.SymlinkInRootfs(t, rootfs, "/opt/java", filepath.Dir(filepath.Dir(hostDir)))
			},
		},
		{
			name: "java launcher symlinked into host JDK",
			setup: func(t *testing.T, rootfs, hostDir string) {
				testutil.SymlinkInRootfs(t, rootfs, "/usr/bin/java", filepath.Join(filepath.Dir(filepath.Dir(hostDir)), "bin/java"))
			},
		},
		{
			name: "JAVA_HOME pointing at host JDK",
			setup: func(t *testing.T, rootfs, hostDir string) {
				testutil.WriteExecutableInRootfs(t, rootfs, "/usr/bin/java")
			},
			hostJavaHome: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// A fake host JDK: <hostJDK>/lib/security/cacerts.
			hostJDK := t.TempDir()
			hostDir := filepath.Join(hostJDK, "lib", "security")
			testutil.WriteExecutableInRootfs(t, hostJDK, "/bin/java")
			original, err := javakeystore.Encode(javakeystore.FormatJKS, []javakeystore.Entry{
				{Alias: "host-root", Cert: newTestCert(t, "host-root")},
			})
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			writeRootfsFile(t, hostJDK, "/lib/security/cacerts", original)
			before := snapshot(t, hostJDK)

			rootfs := t.TempDir()
			tc.setup(t, rootfs, hostDir)

			ctx := newContext(t, rootfs)
			if tc.hostJavaHome {
				ctx.Env = append(ctx.Env, "JAVA_HOME="+hostJDK)
			}
			_ = New().Detect(ctx)
			_ = New().Apply(ctx)

			if after := snapshot(t, hostJDK); !equalSnapshots(before, after) {
				t.Fatalf("Apply() modified host files: before=%v after=%v", keys(before), keys(after))
			}
			// No cacerts exists inside the rootfs, so nothing may be discovered.
			if got := discoverTrustStores(rootfs, ctx.Env); len(got) != 0 {
				t.Fatalf("discoverTrustStores() = %v, want none", got)
			}
		})
	}
}

func newContext(t *testing.T, rootfs string) *hookapi.Context {
	t.Helper()
	caFile := testutil.WriteTempCAFile(t, testutil.CertToPEM(t, newTestCert(t, orgCN)))
	return &hookapi.Context{Rootfs: rootfs, CAFile: caFile, Facts: hookapi.NewMapFactStore()}
}

func writeTrustStore(t *testing.T, rootfs, containerPath string, format javakeystore.Format) {
	t.Helper()

	data, err := javakeystore.Encode(format, []javakeystore.Entry{
		{Alias: "existing-root", Cert: newTestCert(t, "existing-root")},
	})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	writeRootfsFile(t, rootfs, containerPath, data)
}

func writeRootfsFile(t *testing.T, rootfs, containerPath string, data []byte) {
	t.Helper()

	host := containerfs.PathInRootfs(rootfs, containerPath)
	if err := os.MkdirAll(filepath.Dir(host), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(host, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func readTrustStore(t *testing.T, hostPath string) (javakeystore.Format, []javakeystore.Entry) {
	t.Helper()

	format, entries, err := javakeystore.Parse(mustReadFile(t, hostPath))
	if err != nil {
		t.Fatalf("Parse(%q) error = %v", hostPath, err)
	}
	return format, entries
}

func mustReadFile(t *testing.T, hostPath string) []byte {
	t.Helper()

	data, err := os.ReadFile(hostPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", hostPath, err)
	}
	return data
}

// snapshot returns path -> content for every file under dir.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()

	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out[p] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir() error = %v", err)
	}
	return out
}

func equalSnapshots(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func hasCommonName(entries []javakeystore.Entry, cn string) bool {
	for _, e := range entries {
		if e.Cert != nil && e.Cert.Subject.CommonName == cn {
			return true
		}
	}
	return false
}

func aliases(entries []javakeystore.Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Alias)
	}
	return out
}

func newTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	return cert
}
