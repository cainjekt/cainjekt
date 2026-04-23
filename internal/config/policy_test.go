package config

import "testing"

func TestNormalizeInjectionPolicy(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want InjectionPolicy
	}{
		{name: "opt in", in: "opt-in", want: InjectionPolicyOptIn},
		{name: "opt out", in: "opt-out", want: InjectionPolicyOptOut},
		{name: "invalid defaults to opt in", in: "maybe", want: DefaultInjectionPolicy},
		{name: "empty defaults to opt in", in: "", want: DefaultInjectionPolicy},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeInjectionPolicy(tt.in); got != tt.want {
				t.Fatalf("NormalizeInjectionPolicy() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseInjectionPolicy(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want InjectionPolicy
		ok   bool
	}{
		{name: "opt in", in: "opt-in", want: InjectionPolicyOptIn, ok: true},
		{name: "opt out", in: "opt-out", want: InjectionPolicyOptOut, ok: true},
		{name: "invalid", in: "maybe", ok: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := ParseInjectionPolicy(tt.in)
			if ok != tt.ok {
				t.Fatalf("ParseInjectionPolicy() ok = %v, want %v", ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("ParseInjectionPolicy() = %q, want %q", got, tt.want)
			}
		})
	}
}
