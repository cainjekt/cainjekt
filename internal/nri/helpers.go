package nri

import (
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/containerd/nri/pkg/api"
	"github.com/tsuzu/cainjekt/internal/config"
)

func newPlugin(log *slog.Logger) *Plugin {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Plugin{
		log:             log,
		injectionPolicy: injectionPolicyFromEnv(),
	}
}

func shouldInject(pod *api.PodSandbox, policy string) bool {
	if annotations := pod.GetAnnotations(); annotations != nil {
		if raw, ok := annotations[config.AnnoEnabled]; ok {
			switch strings.ToLower(strings.TrimSpace(raw)) {
			case "true":
				return true
			case "false":
				return false
			default:
				return false
			}
		}
	}

	return normalizeInjectionPolicy(policy) == config.InjectionPolicyOptOut
}

func injectionPolicyFromEnv() string {
	return normalizeInjectionPolicy(getenvOr(config.EnvInjectionPolicy, config.DefaultInjectionPolicy))
}

func normalizeInjectionPolicy(policy string) string {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case config.InjectionPolicyOptOut:
		return config.InjectionPolicyOptOut
	default:
		return config.DefaultInjectionPolicy
	}
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
