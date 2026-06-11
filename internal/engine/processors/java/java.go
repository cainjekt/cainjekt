package java

import (
	"fmt"
	"os"
	"path/filepath"

	hookapi "github.com/cainjekt/cainjekt/internal/engine/api"
	"github.com/cainjekt/cainjekt/internal/util/containerfs"
)

const (
	processorName        = "lang-java"
	processorPriority    = 100
	javaBinaryNotFound   = "java binary not found"
	missingContextReason = "missing context"
)

var javaBinaryCandidates = []string{
	"/usr/bin/java",
	"/usr/local/bin/java",
	"/bin/java",
}

// cacertsGlobPatterns are glob patterns (relative to rootfs) used to discover cacerts files.
var cacertsGlobPatterns = []string{
	"/etc/ssl/certs/java/cacerts",
	"/usr/lib/jvm/*/lib/security/cacerts",
	"/usr/lib/jvm/*/jre/lib/security/cacerts",
	"/usr/local/lib/jvm/*/lib/security/cacerts",
	"/usr/local/lib/jvm/*/jre/lib/security/cacerts",
	"/opt/java/*/lib/security/cacerts",
	"/opt/jdk/*/lib/security/cacerts",
}

type processor struct{}

func New() hookapi.Processor {
	return &processor{}
}

func (p *processor) Name() string     { return processorName }
func (p *processor) Category() string { return "language" }

func (p *processor) Detect(ctx *hookapi.Context) hookapi.DetectResult {
	if ctx == nil {
		return hookapi.DetectResult{Applicable: false, Priority: processorPriority, Reason: missingContextReason}
	}
	if containerfs.HasAnyRegularFile(ctx.Rootfs, javaBinaryCandidates) {
		return hookapi.DetectResult{Applicable: true, Priority: processorPriority}
	}
	return hookapi.DetectResult{Applicable: false, Priority: processorPriority, Reason: javaBinaryNotFound}
}

func (p *processor) Apply(ctx *hookapi.Context) error {
	if ctx == nil {
		return nil
	}

	caData, err := os.ReadFile(ctx.CAFile)
	if err != nil {
		return fmt.Errorf("java: failed to read CA bundle: %w", err)
	}

	cacertsFiles := findCACerts(ctx.Rootfs)
	if len(cacertsFiles) == 0 {
		return nil
	}

	for _, hostPath := range cacertsFiles {
		if err := importIntoCACerts(hostPath, caData); err != nil {
			return fmt.Errorf("java: failed to import cert into %s: %w", hostPath, err)
		}
	}
	return nil
}

func findCACerts(rootfs string) []string {
	var found []string
	for _, pattern := range cacertsGlobPatterns {
		hostPattern := containerfs.PathInRootfs(rootfs, pattern)
		matches, err := filepath.Glob(hostPattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			fi, err := os.Stat(match)
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			found = append(found, match)
		}
	}
	return found
}
