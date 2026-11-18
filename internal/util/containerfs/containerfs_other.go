//go:build !linux

package containerfs

import "errors"

var errUnsupported = errors.New("cainjekt requires Linux 5.6+ with openat2(RESOLVE_IN_ROOT)")

// CheckSupport always fails outside Linux.
func CheckSupport() error { return errUnsupported }

func openRoot(string) (rootFS, error) { return nil, errUnsupported }
