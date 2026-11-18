package wrapper

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/cainjekt/cainjekt/internal/config"
	"github.com/cainjekt/cainjekt/internal/runtime/hookctx"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

type execCall struct {
	argv0 string
	argv  []string
	env   []string
}

func stubExec(t *testing.T) *execCall {
	t.Helper()
	call := &execCall{}
	prev := execFunc
	execFunc = func(argv0 string, argv, env []string) error {
		call.argv0, call.argv, call.env = argv0, argv, env
		return nil
	}
	t.Cleanup(func() { execFunc = prev })
	return call
}

func writeContext(t *testing.T, body string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hook-context.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvHookContextFile, p)
}

func envValue(env []string, key string) (string, bool) {
	for _, e := range env {
		if len(e) > len(key) && e[:len(key)+1] == key+"=" {
			return e[len(key)+1:], true
		}
	}
	return "", false
}

func TestRunExecsOriginalWhenContextIsCorrupt(t *testing.T) {
	writeContext(t, "{not json")
	t.Setenv(config.EnvFailPolicy, "")
	call := stubExec(t)

	if err := run(discard, []string{"/bin/true", "arg"}); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if call.argv0 != "/bin/true" || len(call.argv) != 2 {
		t.Fatalf("unexpected exec: %+v", call)
	}
}

func TestRunFailsClosedWhenRequested(t *testing.T) {
	writeContext(t, "{not json")
	t.Setenv(config.EnvFailPolicy, config.FailPolicyClosed)
	stubExec(t)

	if err := run(discard, []string{"/bin/true"}); err == nil {
		t.Fatal("expected error under fail-closed policy")
	}
}

func TestRunAppliesWrapperProcessors(t *testing.T) {
	state := hookctx.State{
		Context: hookctx.PersistedContext{Facts: map[string]string{"individual_ca_path": "/ca.crt"}},
		Detected: []hookctx.DetectedProcessor{
			{Name: "lang-nodejs", Applicable: true},
			{Name: "does-not-exist", Applicable: true},
		},
	}
	b, _ := json.Marshal(state)
	writeContext(t, string(b))
	call := stubExec(t)

	if err := run(discard, []string{"/bin/true"}); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if v, _ := envValue(call.env, "NODE_EXTRA_CA_CERTS"); v != "/ca.crt" {
		t.Fatalf("NODE_EXTRA_CA_CERTS = %q", v)
	}
}

func TestRunMissingContextIsNoop(t *testing.T) {
	t.Setenv(config.EnvHookContextFile, filepath.Join(t.TempDir(), "missing.json"))
	t.Setenv("CAINJEKT_TEST_KEEP", "1")
	call := stubExec(t)

	if err := run(discard, []string{"/bin/true"}); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if v, _ := envValue(call.env, "CAINJEKT_TEST_KEEP"); v != "1" {
		t.Fatal("original environment not preserved")
	}
}

func TestExecCommandResolvesWithTargetPATH(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mycmd")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	call := stubExec(t)
	if err := execCommand([]string{"mycmd"}, []string{"PATH=" + dir}); err != nil {
		t.Fatalf("execCommand() error = %v", err)
	}
	if call.argv0 != bin {
		t.Fatalf("argv0 = %q, want %q", call.argv0, bin)
	}
	if err := execCommand([]string{"definitely-not-a-command"}, []string{"PATH=" + dir}); err == nil {
		t.Fatal("expected resolution error")
	}
}
