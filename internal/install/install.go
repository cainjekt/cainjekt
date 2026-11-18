// Package install implements the `cainjekt install` subcommand, which copies
// the running cainjekt executable to a host path. The DaemonSet's
// initContainer uses it to place the binary where containerd can execute it
// as an OCI hook and bind-mount it into containers, so no shell or separate
// installer image is needed.
package install

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

// Command is the subcommand name dispatched by the app.
const Command = "install"

// DefaultDest is the install destination as seen from the initContainer,
// which mounts host /opt/cainjekt at /host/opt/cainjekt.
const DefaultDest = "/host/opt/cainjekt/bin/cainjekt"

const binaryMode os.FileMode = 0o755

// Run parses the subcommand flags and installs the running executable.
func Run(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet(Command, flag.ContinueOnError)
	dest := fs.String("dest", DefaultDest, "destination path of the installed binary")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}

	src, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine executable path: %w", err)
	}
	if err := Copy(src, *dest); err != nil {
		return err
	}
	log.Info("installed plugin binary", "src", src, "dest", *dest)
	return nil
}

// Copy atomically installs src at dest with mode 0755: it writes a temporary
// file in the destination directory and renames it over dest. Renaming
// (instead of writing in place) keeps an already running or bind-mounted old
// binary intact and avoids ETXTBSY, and readers never see a partial file.
func Copy(src, dest string) (err error) {
	if dest == "" {
		return errors.New("destination path is empty")
	}
	if fi, lerr := os.Lstat(dest); lerr == nil && fi.IsDir() {
		return fmt.Errorf("destination %s is a directory", dest)
	}

	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source %s: %w", src, err)
	}
	defer func() { _ = in.Close() }()

	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create destination directory %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".cainjekt-install-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = io.Copy(tmp, in); err != nil {
		return fmt.Errorf("failed to copy %s to %s: %w", src, tmpName, err)
	}
	if err = tmp.Chmod(binaryMode); err != nil {
		return fmt.Errorf("failed to chmod %s: %w", tmpName, err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("failed to sync %s: %w", tmpName, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("failed to close %s: %w", tmpName, err)
	}
	if err = os.Rename(tmpName, dest); err != nil {
		return fmt.Errorf("failed to rename %s to %s: %w", tmpName, dest, err)
	}
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
