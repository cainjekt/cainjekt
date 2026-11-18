package nri

import (
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/cainjekt/cainjekt/internal/config"
	"github.com/containerd/nri/pkg/api"
)

func newPlugin(log *slog.Logger) *Plugin {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Plugin{
		log:            log,
		tracked:        newTracker(),
		failPolicy:     config.FailPolicyOpen,
		hookTimeoutSec: config.DefaultHookTimeoutSec,
		specTrustEnv:   true,
	}
}

func shouldInject(pod *api.PodSandbox) bool {
	return strings.EqualFold(pod.GetAnnotations()[config.AnnoEnabled], "true")
}

// unknownCainjektKeys returns pod annotation keys that use the cainjekt
// prefix but are not recognized, usually a typo such as ".../enable" for
// ".../enabled" that would otherwise silently disable injection.
func unknownCainjektKeys(pod *api.PodSandbox) []string {
	known := map[string]struct{}{
		config.AnnoEnabled:           {},
		config.AnnoProcessorsInclude: {},
		config.AnnoProcessorsExclude: {},
	}
	var out []string
	for k := range pod.GetAnnotations() {
		if !strings.HasPrefix(k, config.AnnoPrefix) {
			continue
		}
		if _, ok := known[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func hasEnv(env []string, key string) bool {
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return true
		}
	}
	return false
}

func getenvOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
