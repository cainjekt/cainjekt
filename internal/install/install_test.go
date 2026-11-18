package install

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func writeSrc(t *testing.T, content []byte) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return src
}

func TestCopyCreatesDirAndSetsMode(t *testing.T) {
	content := []byte("binary-v1")
	src := writeSrc(t, content)
	dest := filepath.Join(t.TempDir(), "opt", "cainjekt", "bin", "cainjekt")

	if err := Copy(src, dest); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content = %q, want %q", got, content)
	}
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %v, want 0755", fi.Mode().Perm())
	}
}

func TestCopyReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "cainjekt")
	if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Keep the old file open, as a running process or bind mount would.
	old, err := os.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = old.Close() }()

	if err := Copy(writeSrc(t, []byte("new")), dest); err != nil {
		t.Fatalf("Copy: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("dest = %q, want new", got)
	}
	oldContent, err := io.ReadAll(old)
	if err != nil {
		t.Fatal(err)
	}
	if string(oldContent) != "old" {
		t.Fatalf("old inode content = %q, want old (rename must not modify it in place)", oldContent)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("leftover files in dest dir: %v", entries)
	}
}

func TestCopyRejectsDirectoryDest(t *testing.T) {
	dir := t.TempDir()
	if err := Copy(writeSrc(t, []byte("x")), dir); err == nil {
		t.Fatal("expected error for directory destination")
	}
}

func TestCopyMissingSource(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "cainjekt")
	if err := Copy(filepath.Join(t.TempDir(), "missing"), dest); err == nil {
		t.Fatal("expected error for missing source")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("dest should not exist, stat err = %v", err)
	}
}

func TestRunInstallsExecutable(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "bin", "cainjekt")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := Run(log, []string{"--dest", dest}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("installed binary differs from the running executable")
	}
}

func TestRunRejectsExtraArgs(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := Run(log, []string{"--dest", filepath.Join(t.TempDir(), "x"), "extra"}); err == nil {
		t.Fatal("expected error for extra arguments")
	}
}
