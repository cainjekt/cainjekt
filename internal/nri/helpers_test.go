package nri

import (
	"io"
	"log/slog"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"github.com/tsuzu/cainjekt/internal/config"
)

func TestShouldInject(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		namespace         string
		annotations       map[string]string
		policy            config.InjectionPolicy
		namespacePolicies map[string]config.InjectionPolicy
		want              bool
	}{
		{
			name:   "opt in default without annotation",
			policy: config.InjectionPolicyOptIn,
			want:   false,
		},
		{
			name:   "opt out default without annotation",
			policy: config.InjectionPolicyOptOut,
			want:   true,
		},
		{
			name:      "namespace opt in overrides global opt out",
			namespace: "kube-system",
			policy:    config.InjectionPolicyOptOut,
			namespacePolicies: map[string]config.InjectionPolicy{
				"kube-system": config.InjectionPolicyOptIn,
			},
			want: false,
		},
		{
			name:      "namespace opt out overrides global opt in",
			namespace: "tenant-a",
			policy:    config.InjectionPolicyOptIn,
			namespacePolicies: map[string]config.InjectionPolicy{
				"tenant-a": config.InjectionPolicyOptOut,
			},
			want: true,
		},
		{
			name:        "annotation true overrides opt in",
			annotations: map[string]string{config.AnnoEnabled: "true"},
			policy:      config.InjectionPolicyOptIn,
			want:        true,
		},
		{
			name:        "annotation true overrides namespace opt in",
			namespace:   "kube-system",
			annotations: map[string]string{config.AnnoEnabled: "true"},
			policy:      config.InjectionPolicyOptOut,
			namespacePolicies: map[string]config.InjectionPolicy{
				"kube-system": config.InjectionPolicyOptIn,
			},
			want: true,
		},
		{
			name:        "annotation false overrides namespace opt out",
			namespace:   "tenant-a",
			annotations: map[string]string{config.AnnoEnabled: "false"},
			policy:      config.InjectionPolicyOptIn,
			namespacePolicies: map[string]config.InjectionPolicy{
				"tenant-a": config.InjectionPolicyOptOut,
			},
			want: false,
		},
		{
			name:        "annotation false overrides opt out",
			annotations: map[string]string{config.AnnoEnabled: "false"},
			policy:      config.InjectionPolicyOptOut,
			want:        false,
		},
		{
			name:        "invalid annotation stays disabled",
			annotations: map[string]string{config.AnnoEnabled: "maybe"},
			policy:      config.InjectionPolicyOptOut,
			want:        false,
		},
		{
			name: "zero value policy behaves like opt in",
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pod := &api.PodSandbox{
				Namespace:   tt.namespace,
				Annotations: tt.annotations,
			}
			if got := shouldInject(pod, tt.policy, tt.namespacePolicies); got != tt.want {
				t.Fatalf("shouldInject() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNamespaceInjectionPolicy(t *testing.T) {
	tests := []struct {
		name              string
		namespace         string
		globalPolicy      config.InjectionPolicy
		namespacePolicies map[string]config.InjectionPolicy
		want              config.InjectionPolicy
	}{
		{
			name:         "defaults to global policy",
			namespace:    "default",
			globalPolicy: config.InjectionPolicyOptOut,
			want:         config.InjectionPolicyOptOut,
		},
		{
			name:         "namespace opt in overrides global opt out",
			namespace:    "kube-system",
			globalPolicy: config.InjectionPolicyOptOut,
			namespacePolicies: map[string]config.InjectionPolicy{
				"kube-system": config.InjectionPolicyOptIn,
			},
			want: config.InjectionPolicyOptIn,
		},
		{
			name:         "namespace opt out overrides global opt in",
			namespace:    "tenant-a",
			globalPolicy: config.InjectionPolicyOptIn,
			namespacePolicies: map[string]config.InjectionPolicy{
				"tenant-a": config.InjectionPolicyOptOut,
			},
			want: config.InjectionPolicyOptOut,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := namespaceInjectionPolicy(tt.namespace, tt.globalPolicy, tt.namespacePolicies); got != tt.want {
				t.Fatalf("namespaceInjectionPolicy() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseNamespacePolicies(t *testing.T) {
	got := parseNamespacePolicies(" kube-system=opt-in, tenant-a=opt-out, broken, empty= , invalid=maybe ")
	want := map[string]config.InjectionPolicy{
		"kube-system": config.InjectionPolicyOptIn,
		"tenant-a":    config.InjectionPolicyOptOut,
	}
	if len(got) != len(want) {
		t.Fatalf("parseNamespacePolicies() len = %d, want %d, got=%v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("parseNamespacePolicies()[%q] = %q, want %q", k, got[k], v)
		}
	}
}

func TestNewPluginReadsInjectionPolicyFromEnv(t *testing.T) {
	t.Setenv(config.EnvInjectionPolicy, string(config.InjectionPolicyOptOut))
	t.Setenv(config.EnvNamespacePolicies, "kube-system=opt-in,monitoring=opt-out")

	p := newPlugin(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if p.injectionPolicy != config.InjectionPolicyOptOut {
		t.Fatalf("newPlugin() policy = %q, want %q", p.injectionPolicy, config.InjectionPolicyOptOut)
	}
	if p.namespacePolicies["kube-system"] != config.InjectionPolicyOptIn {
		t.Fatalf("newPlugin() namespacePolicies[kube-system] = %q, want %q", p.namespacePolicies["kube-system"], config.InjectionPolicyOptIn)
	}
	if p.namespacePolicies["monitoring"] != config.InjectionPolicyOptOut {
		t.Fatalf("newPlugin() namespacePolicies[monitoring] = %q, want %q", p.namespacePolicies["monitoring"], config.InjectionPolicyOptOut)
	}
}
