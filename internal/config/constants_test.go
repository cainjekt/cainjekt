package config

import (
	"testing"
	"time"
)

func TestParseFailPolicy(t *testing.T) {
	for in, want := range map[string]string{"": FailPolicyOpen, " Fail-Open ": FailPolicyOpen, "fail-closed": FailPolicyClosed} {
		got, err := ParseFailPolicy(in)
		if err != nil || got != want {
			t.Fatalf("ParseFailPolicy(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseFailPolicy("closed"); err == nil {
		t.Fatal("expected error for unknown policy")
	}
}

func TestParseHookTimeoutSec(t *testing.T) {
	if n, err := ParseHookTimeoutSec(""); err != nil || n != DefaultHookTimeoutSec {
		t.Fatalf("default = %d, %v", n, err)
	}
	if n, err := ParseHookTimeoutSec("30"); err != nil || n != 30 {
		t.Fatalf("30 = %d, %v", n, err)
	}
	for _, bad := range []string{"1", "121", "x", "-5"} {
		if _, err := ParseHookTimeoutSec(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestHookBudget(t *testing.T) {
	if HookBudget(20) != 19*time.Second || HookBudget(2) != time.Second {
		t.Fatal("unexpected budget")
	}
}
