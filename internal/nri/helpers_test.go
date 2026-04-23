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
		name        string
		annotations map[string]string
		policy      string
		want        bool
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
			name:        "annotation true overrides opt in",
			annotations: map[string]string{config.AnnoEnabled: "true"},
			policy:      config.InjectionPolicyOptIn,
			want:        true,
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
			name:   "unknown policy falls back to opt in",
			policy: "unexpected",
			want:   false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pod := &api.PodSandbox{Annotations: tt.annotations}
			if got := shouldInject(pod, tt.policy); got != tt.want {
				t.Fatalf("shouldInject() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewPluginReadsInjectionPolicyFromEnv(t *testing.T) {
	t.Setenv(config.EnvInjectionPolicy, config.InjectionPolicyOptOut)

	p := newPlugin(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if p.injectionPolicy != config.InjectionPolicyOptOut {
		t.Fatalf("newPlugin() policy = %q, want %q", p.injectionPolicy, config.InjectionPolicyOptOut)
	}
}
