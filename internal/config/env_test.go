package config

import "testing"

func TestGetenvOr(t *testing.T) {
	const key = "CAINJEKT_TEST_GETENV_OR"
	for _, tc := range []struct {
		name, value, want string
	}{
		{"unset", "", "fallback"},
		{"blank", "   ", "fallback"},
		{"trimmed", "  value \n", "value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(key, tc.value)
			if got := GetenvOr(key, "fallback"); got != tc.want {
				t.Fatalf("GetenvOr() = %q, want %q", got, tc.want)
			}
		})
	}
}
