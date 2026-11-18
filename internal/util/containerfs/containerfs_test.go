package containerfs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func mkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	mkdir(t, filepath.Dir(link))
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, p, body string) {
	t.Helper()
	mkdir(t, filepath.Dir(p))
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestResolveSymlinks(t *testing.T) {
	t.Parallel()
	rootfs := t.TempDir()
	mkdir(t, filepath.Join(rootfs, "real", "ssl"))
	mkdir(t, filepath.Join(rootfs, "usr", "lib"))
	symlink(t, "/real/ssl/ca-bundle.pem", filepath.Join(rootfs, "etc", "ssl-bundle.pem"))
	symlink(t, "../usr/lib", filepath.Join(rootfs, "etc", "ssl"))
	symlink(t, "../../../../../../usr/lib", filepath.Join(rootfs, "etc", "deep"))
	symlink(t, "loop2", filepath.Join(rootfs, "loop1"))
	symlink(t, "loop1", filepath.Join(rootfs, "loop2"))

	cases := map[string]string{
		"/etc/ssl-bundle.pem":          "/real/ssl/ca-bundle.pem",
		"/etc/ssl/ca-certificates.crt": "/usr/lib/ca-certificates.crt",
		"/etc/deep/x":                  "/usr/lib/x",
		"/missing/a/b":                 "/missing/a/b",
		"/":                            "/",
	}
	for in, want := range cases {
		got, err := ResolveSymlinks(rootfs, in)
		if err != nil {
			t.Fatalf("ResolveSymlinks(%q) error = %v", in, err)
		}
		if got != want {
			t.Fatalf("ResolveSymlinks(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := ResolveSymlinks(rootfs, "/loop1"); err == nil {
		t.Fatal("expected error for symlink loop")
	}
}

// An image may ship /etc/cainjekt (or any parent of a path the hook writes)
// as an absolute symlink to a host directory. The write must land inside the
// rootfs, never on the host.
func TestWriteFileNeverEscapesViaAbsoluteDirSymlink(t *testing.T) {
	t.Parallel()
	rootfs := t.TempDir()
	host := t.TempDir() // stands in for a host directory such as /etc/cron.d
	symlink(t, host, filepath.Join(rootfs, "etc", "cainjekt"))

	resolved, err := WriteFile(rootfs, "/etc/cainjekt/hook-context.json", []byte("x"), 0o644)
	if err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(host, "hook-context.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file escaped to host directory: stat err = %v", err)
	}
	want := filepath.ToSlash(filepath.Join(host, "hook-context.json"))
	if resolved != want {
		t.Fatalf("resolved = %q, want re-anchored %q", resolved, want)
	}
	if _, err := os.Stat(PathInRootfs(rootfs, resolved)); err != nil {
		t.Fatalf("file not written inside rootfs: %v", err)
	}
}

func TestWriteFileNeverEscapesViaDotDot(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	rootfs := filepath.Join(parent, "rootfs")
	mkdir(t, rootfs)
	symlink(t, "../../..", filepath.Join(rootfs, "etc", "up"))

	if _, err := WriteFile(rootfs, "/etc/up/escape", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(parent, "escape")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file escaped rootfs: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rootfs, "escape")); err != nil {
		t.Fatalf("expected file at rootfs top: %v", err)
	}
}

func TestWriteFileRefusesSymlinkAndNonRegular(t *testing.T) {
	t.Parallel()
	rootfs := t.TempDir()
	mkdir(t, filepath.Join(rootfs, "etc", "dir"))
	if _, err := WriteFile(rootfs, "/etc/dir", []byte("x"), 0o644); err == nil {
		t.Fatal("expected error when target is a directory")
	}
	if _, err := WriteFile(rootfs, "/", []byte("x"), 0o644); err == nil {
		t.Fatal("expected error for rootfs root")
	}
}

func TestWriteFilePreservesMode(t *testing.T) {
	t.Parallel()
	rootfs := t.TempDir()
	p := filepath.Join(rootfs, "etc", "f")
	writeFile(t, p, "old")
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteFile(rootfs, "/etc/f", []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".cainjekt-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestReadFileStaysInRootfs(t *testing.T) {
	t.Parallel()
	rootfs := t.TempDir()
	host := t.TempDir()
	writeFile(t, filepath.Join(host, "os-release"), "ID=host\n")
	writeFile(t, filepath.Join(rootfs, "usr", "lib", "os-release"), "ID=image\n")
	// Absolute link as the image sees it: must resolve inside the rootfs.
	symlink(t, "/usr/lib/os-release", filepath.Join(rootfs, "etc", "os-release"))
	// Link to a host path: must not read the host file.
	symlink(t, filepath.Join(host, "os-release"), filepath.Join(rootfs, "etc", "hostlink"))

	data, resolved, err := ReadFile(rootfs, "/etc/os-release")
	if err != nil || string(data) != "ID=image\n" || resolved != "/usr/lib/os-release" {
		t.Fatalf("ReadFile() = %q, %q, %v", data, resolved, err)
	}
	if _, _, err := ReadFile(rootfs, "/etc/hostlink"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected ErrNotExist for re-anchored host link, got %v", err)
	}
}

func TestReadFileRejectsFIFO(t *testing.T) {
	t.Parallel()
	rootfs := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(rootfs, "fifo"), 0o644); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	if _, _, err := ReadFile(rootfs, "/fifo"); err == nil {
		t.Fatal("expected error reading FIFO")
	}
}

func TestReadFileRejectsOversized(t *testing.T) {
	t.Parallel()
	rootfs := t.TempDir()
	f, err := os.Create(filepath.Join(rootfs, "big"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxReadSize + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, _, err := ReadFile(rootfs, "/big"); err == nil {
		t.Fatal("expected error for oversized file")
	}
}

func TestHasAnyRegularFileDoesNotFollowToHost(t *testing.T) {
	t.Parallel()
	rootfs := t.TempDir()
	host := t.TempDir()
	writeFile(t, filepath.Join(host, "node"), "bin")
	symlink(t, filepath.Join(host, "node"), filepath.Join(rootfs, "usr", "bin", "node"))
	if HasAnyRegularFile(rootfs, []string{"/usr/bin/node"}) {
		t.Fatal("detected a binary that only exists on the host")
	}
	writeFile(t, filepath.Join(rootfs, "usr", "local", "bin", "node"), "bin")
	symlink(t, "/usr/local/bin/node", filepath.Join(rootfs, "bin", "node"))
	if !HasAnyRegularFile(rootfs, []string{"/bin/node"}) {
		t.Fatal("absolute in-image symlink should be followed inside rootfs")
	}
}
