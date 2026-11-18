// Package containerfs is the only way hook-phase code may touch a container
// rootfs.
//
// The hook runs as root in the host mount namespace, while the rootfs content
// comes from an untrusted image. Every helper here therefore:
//
//   - takes container-absolute paths, never host paths;
//   - resolves symlinks as the container would see them (absolute targets are
//     re-anchored to the rootfs, never to the host root);
//   - performs the actual I/O through an os.Root, so even a path that changes
//     between resolution and use can never escape the rootfs;
//   - reads only bounded regular files (no FIFOs, devices or huge files);
//   - never replaces a symlink.
//
// The forbidigo rule in .golangci.yml rejects direct os/filepath file access
// in hook-phase packages so new code cannot bypass these rules.
package containerfs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

// MaxReadSize caps reads of files that come from a container image. Real trust
// stores are well under 1 MiB; the cap only stops an image from making the hook
// read without bound.
const MaxReadSize = 16 << 20

const maxSymlinkHops = 40

// PathInRootfs joins a container-absolute path onto the host rootfs path
// WITHOUT resolving symlinks. It must only be used for paths that were already
// resolved with ResolveSymlinks, or for building test fixtures.
func PathInRootfs(rootfs, containerPath string) string {
	return filepath.Join(rootfs, filepath.FromSlash(relPath(containerPath)))
}

// ResolveSymlinks resolves containerPath to a container-absolute path,
// following symlinks within the rootfs only: absolute targets are re-anchored
// to the rootfs instead of the host root, and ".." never climbs above "/".
// The returned path may not exist (dangling links and missing components
// resolve to their would-be location).
func ResolveSymlinks(rootfs, containerPath string) (string, error) {
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return "", fmt.Errorf("failed to open rootfs %s: %w", rootfs, err)
	}
	defer func() { _ = root.Close() }()
	return resolve(root, containerPath)
}

func resolve(root *os.Root, containerPath string) (string, error) {
	remaining := splitContainerPath(containerPath)
	resolved := make([]string, 0, len(remaining))
	hops := 0

	for len(remaining) > 0 {
		part := remaining[0]
		remaining = remaining[1:]
		candidate := strings.Join(append(append([]string{}, resolved...), part), "/")
		fi, err := root.Lstat(candidate)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				resolved = append(resolved, part)
				resolved = append(resolved, remaining...)
				break
			}
			return "", fmt.Errorf("failed to stat /%s: %w", candidate, err)
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			resolved = append(resolved, part)
			continue
		}

		hops++
		if hops > maxSymlinkHops {
			return "", fmt.Errorf("too many symlink hops while resolving %s", containerPath)
		}
		target, err := root.Readlink(candidate)
		if err != nil {
			return "", fmt.Errorf("failed to read symlink /%s: %w", candidate, err)
		}
		next := target
		if !path.IsAbs(target) {
			next = path.Join("/"+strings.Join(resolved, "/"), target)
		}
		remaining = append(splitContainerPath(next), remaining...)
		resolved = resolved[:0]
	}

	return "/" + strings.Join(resolved, "/"), nil
}

// RegularFile reports whether containerPath resolves to a regular file in the
// rootfs, and returns the resolved container path.
func RegularFile(rootfs, containerPath string) (string, bool) {
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return "", false
	}
	defer func() { _ = root.Close() }()
	resolved, err := resolve(root, containerPath)
	if err != nil {
		return "", false
	}
	fi, err := root.Lstat(relPath(resolved))
	return resolved, err == nil && fi.Mode().IsRegular()
}

// HasAnyRegularFile reports whether any of containerPaths resolves to a
// regular file inside the rootfs.
func HasAnyRegularFile(rootfs string, containerPaths []string) bool {
	for _, p := range containerPaths {
		if _, ok := RegularFile(rootfs, p); ok {
			return true
		}
	}
	return false
}

// ReadFile reads containerPath from the rootfs and returns the content and the
// resolved container path. Only regular files up to MaxReadSize are read. A
// missing file returns an error wrapping os.ErrNotExist.
func ReadFile(rootfs, containerPath string) ([]byte, string, error) {
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open rootfs %s: %w", rootfs, err)
	}
	defer func() { _ = root.Close() }()
	resolved, err := resolve(root, containerPath)
	if err != nil {
		return nil, "", err
	}
	data, err := readRegular(root, relPath(resolved))
	return data, resolved, err
}

func readRegular(root *os.Root, rel string) ([]byte, error) {
	// Lstat first so a device node is never opened: opening some devices has
	// side effects of its own.
	fi, err := root.Lstat(rel)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing to read /%s: not a regular file (%s)", rel, fi.Mode().Type())
	}
	// O_NONBLOCK: a FIFO swapped in after Lstat must not block the hook.
	f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if fi, err = f.Stat(); err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing to read /%s: not a regular file (%s)", rel, fi.Mode().Type())
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxReadSize+1))
	if err != nil {
		return nil, err
	}
	// Never truncate: a partial trust store written back would drop CAs.
	if len(data) > MaxReadSize {
		return nil, fmt.Errorf("refusing to read /%s: larger than %d bytes", rel, MaxReadSize)
	}
	return data, nil
}

// WriteFile atomically replaces containerPath in the rootfs, creating missing
// parent directories, and returns the resolved container path. It refuses to
// replace a symlink or a non-regular file and keeps the existing file's mode
// and owner; new files get fallbackMode.
func WriteFile(rootfs, containerPath string, data []byte, fallbackMode os.FileMode) (string, error) {
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return "", fmt.Errorf("failed to open rootfs %s: %w", rootfs, err)
	}
	defer func() { _ = root.Close() }()
	resolved, err := resolve(root, containerPath)
	if err != nil {
		return "", err
	}
	if resolved == "/" {
		return "", errors.New("refusing to write to rootfs root")
	}
	rel := relPath(resolved)
	dir := path.Dir(rel)
	if err := root.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create directory for %s: %w", resolved, err)
	}
	if err := atomicWrite(root, rel, data, fallbackMode); err != nil {
		return "", fmt.Errorf("failed to write %s: %w", resolved, err)
	}
	return resolved, nil
}

func atomicWrite(root *os.Root, rel string, data []byte, fallbackMode os.FileMode) error {
	if fallbackMode == 0 {
		fallbackMode = 0o644
	}
	mode := fallbackMode
	uid, gid := -1, -1
	fi, err := root.Lstat(rel)
	switch {
	case err == nil:
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to overwrite symlink /%s", rel)
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("refusing to overwrite /%s: not a regular file (%s)", rel, fi.Mode().Type())
		}
		mode = fi.Mode().Perm()
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			uid, gid = int(st.Uid), int(st.Gid)
		}
	case !errors.Is(err, os.ErrNotExist):
		return err
	}

	tmp, err := tempName(rel)
	if err != nil {
		return err
	}
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = f.Close()
		if !committed {
			_ = root.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if uid >= 0 && gid >= 0 {
		if err := f.Chown(uid, gid); err != nil && !errors.Is(err, os.ErrPermission) {
			return err
		}
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := root.Rename(tmp, rel); err != nil {
		return err
	}
	committed = true
	if d, err := root.Open(path.Dir(rel)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func tempName(rel string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return path.Join(path.Dir(rel), ".cainjekt-"+hex.EncodeToString(b[:])), nil
}

// Glob returns the container paths matching a rootfs-relative pattern (no
// leading slash). Matching runs on an os.Root, so links pointing out of the
// rootfs are never followed.
func Glob(rootfs, pattern string) []string {
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return nil
	}
	defer func() { _ = root.Close() }()
	matches, err := fs.Glob(root.FS(), pattern)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, "/"+m)
	}
	return out
}

func relPath(containerPath string) string {
	clean := path.Clean("/" + strings.TrimSpace(containerPath))
	if clean == "/" {
		return "."
	}
	return strings.TrimPrefix(clean, "/")
}

func splitContainerPath(p string) []string {
	rel := relPath(p)
	if rel == "." {
		return nil
	}
	return strings.Split(rel, "/")
}
