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
		log:               log,
		injectionPolicy:   injectionPolicyFromEnv(),
		namespacePolicies: namespacePoliciesFromEnv(),
	}
}

func shouldInject(pod *api.PodSandbox, policy config.InjectionPolicy, namespacePolicies map[string]config.InjectionPolicy) bool {
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

	return namespaceInjectionPolicy(pod.GetNamespace(), policy, namespacePolicies) == config.InjectionPolicyOptOut
}

func injectionPolicyFromEnv() config.InjectionPolicy {
	return config.NormalizeInjectionPolicy(getenvOr(config.EnvInjectionPolicy, string(config.DefaultInjectionPolicy)))
}

func namespacePoliciesFromEnv() map[string]config.InjectionPolicy {
	return parseNamespacePolicies(getenvOr(config.EnvNamespacePolicies, ""))
}

func parseNamespacePolicies(raw string) map[string]config.InjectionPolicy {
	out := map[string]config.InjectionPolicy{}
	for _, item := range strings.Split(raw, ",") {
		entry := strings.TrimSpace(item)
		if entry == "" {
			continue
		}
		namespace, policy, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		namespace = strings.ToLower(strings.TrimSpace(namespace))
		if namespace == "" {
			continue
		}
		normalizedPolicy, ok := config.ParseInjectionPolicy(policy)
		if !ok {
			continue
		}
		out[namespace] = normalizedPolicy
	}
	return out
}

func namespaceInjectionPolicy(namespace string, globalPolicy config.InjectionPolicy, namespacePolicies map[string]config.InjectionPolicy) config.InjectionPolicy {
	if policy, ok := namespacePolicies[strings.ToLower(strings.TrimSpace(namespace))]; ok {
		return policy
	}
	return globalPolicy
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
