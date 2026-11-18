package processors

import (
	"testing"

	"github.com/cainjekt/cainjekt/internal/testutil"
)

func TestMain(m *testing.M) { testutil.RunIfContainerfsSupported(m) }
