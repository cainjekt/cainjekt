package app

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/cainjekt/cainjekt/internal/config"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func stubHook(t *testing.T, f func(*slog.Logger) error) {
	t.Helper()
	prev := hookRun
	hookRun = f
	t.Cleanup(func() { hookRun = prev })
}

func TestRunHookGivesUpBeforeRuntimeTimeoutFailOpen(t *testing.T) {
	t.Setenv(config.EnvFailPolicy, config.FailPolicyOpen)
	t.Setenv(config.EnvHookTimeoutSec, "2") // budget: 1s
	stubHook(t, func(*slog.Logger) error { time.Sleep(10 * time.Second); return nil })

	start := time.Now()
	if err := runHook(discard); err != nil {
		t.Fatalf("runHook() error = %v, want nil under fail-open", err)
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("runHook() took %s, want ~1s", d)
	}
}

func TestRunHookFailClosedPropagatesErrors(t *testing.T) {
	t.Setenv(config.EnvFailPolicy, config.FailPolicyClosed)
	stubHook(t, func(*slog.Logger) error { return errors.New("boom") })
	if err := runHook(discard); err == nil {
		t.Fatal("expected error under fail-closed")
	}
}

func TestRunHookFailOpenSwallowsErrors(t *testing.T) {
	t.Setenv(config.EnvFailPolicy, "")
	stubHook(t, func(*slog.Logger) error { return errors.New("boom") })
	if err := runHook(discard); err != nil {
		t.Fatalf("runHook() error = %v", err)
	}
}
