package python

import (
	"strings"

	hookapi "github.com/cainjekt/cainjekt/internal/engine/api"
	"github.com/cainjekt/cainjekt/internal/util/containerfs"
	"github.com/cainjekt/cainjekt/internal/util/envutil"
)

const (
	processorName        = "lang-python"
	processorPriority    = 100
	envSSLCAFile         = "SSL_CERT_FILE"
	envRequestsCABundle  = "REQUESTS_CA_BUNDLE"
	pythonBinaryNotFound = "python binary not found"
	missingContextReason = "missing context"
)

var pythonBinaryCandidates = []string{
	"/usr/bin/python3",
	"/usr/local/bin/python3",
	"/bin/python3",
	"/usr/bin/python",
	"/usr/local/bin/python",
	"/bin/python",
}

type processor struct{}

func New() hookapi.Processor {
	return &processor{}
}

func (p *processor) Name() string { return processorName }

func (p *processor) Category() string { return "language" }

func (p *processor) Detect(ctx *hookapi.Context) hookapi.DetectResult {
	if ctx == nil {
		return hookapi.DetectResult{Applicable: false, Priority: processorPriority, Reason: missingContextReason}
	}
	if hasPythonBinary(ctx.Rootfs) {
		return hookapi.DetectResult{Applicable: true, Priority: processorPriority}
	}
	return hookapi.DetectResult{Applicable: false, Priority: processorPriority, Reason: pythonBinaryNotFound}
}

func (p *processor) Apply(_ *hookapi.Context) error {
	return nil
}

func (p *processor) ApplyWrapper(ctx *hookapi.Context) error {
	if ctx == nil || ctx.Facts == nil {
		return nil
	}
	// SSL_CERT_FILE and REQUESTS_CA_BUNDLE REPLACE the trust store, so they
	// must point at the merged bundle (system roots + org CA). Pointing them at
	// the bare org CA would break all public TLS. Without a merged bundle we
	// leave them unset rather than degrade.
	bundle, ok := ctx.Facts.Get(hookapi.FactTrustStorePath)
	if !ok {
		return nil
	}
	bundle = strings.TrimSpace(bundle)
	if bundle == "" {
		return nil
	}
	ctx.Env = envutil.Upsert(ctx.Env, envSSLCAFile, bundle)
	ctx.Env = envutil.Upsert(ctx.Env, envRequestsCABundle, bundle)
	return nil
}

// TODO: Make rootfs binary detection handle absolute symlinks without resolving them on the host.
func hasPythonBinary(rootfs string) bool {
	return containerfs.HasAnyRegularFile(rootfs, pythonBinaryCandidates)
}
