//go:build linux

package containerfs

import (
	"fmt"

	chrootfs "github.com/tsuzu/go-chrootfs"
)

// CheckSupport reports whether the running kernel provides the openat2
// RESOLVE_IN_ROOT semantics containerfs depends on (Linux 5.6+). Older kernels
// are not supported.
func CheckSupport() error {
	if err := chrootfs.CheckSupport(); err != nil {
		return fmt.Errorf("cainjekt requires Linux 5.6+ with openat2(RESOLVE_IN_ROOT): %w", err)
	}
	return nil
}

func openRoot(rootfs string) (rootFS, error) {
	r, err := chrootfs.New(rootfs)
	if err != nil {
		return nil, fmt.Errorf("failed to open rootfs %s: %w", rootfs, err)
	}
	return r, nil
}
