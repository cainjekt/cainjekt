package containerfs

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if err := CheckSupport(); err != nil {
		fmt.Fprintf(os.Stderr, "SKIP: %v\n", err)
		os.Exit(0)
	}
	os.Exit(m.Run())
}
