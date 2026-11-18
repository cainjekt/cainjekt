package nri

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cainjekt/cainjekt/internal/config"
	"github.com/containerd/nri/pkg/api"
)

func TestCreateContainerStagesDynamicCAForHook(t *testing.T) {
	t.Setenv(config.EnvCAFile, writeTempSourceCA(t))
	t.Setenv(config.EnvDynamicCARoot, t.TempDir())

	p := newPlugin(slog.New(slog.NewTextHandler(io.Discard, nil)))
	pod := &api.PodSandbox{
		Namespace:   "default",
		Name:        "pod-a",
		Annotations: map[string]string{config.AnnoEnabled: "true"},
	}
	ctr := &api.Container{
		Id:   "containerd://abcd1234",
		Name: "app",
		Args: []string{"sh", "-c", "sleep 10"},
	}

	adj, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("CreateContainer() error = %v", err)
	}
	if adj == nil || adj.GetHooks() == nil || len(adj.GetHooks().GetCreateRuntime()) == 0 {
		t.Fatalf("CreateContainer() did not include createRuntime hook")
	}

	hook := adj.GetHooks().GetCreateRuntime()[0]
	caPath := envValue(hook.GetEnv(), config.EnvCAFile)
	if caPath == "" {
		t.Fatalf("hook env %q is empty", config.EnvCAFile)
	}
	if caPath == os.Getenv(config.EnvCAFile) {
		t.Fatalf("hook env should use dynamic CA path, got source path: %q", caPath)
	}
	if !strings.HasPrefix(caPath, os.Getenv(config.EnvDynamicCARoot)+string(os.PathSeparator)) {
		t.Fatalf("hook env path %q is not under dynamic root %q", caPath, os.Getenv(config.EnvDynamicCARoot))
	}

	got, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", caPath, err)
	}
	src, err := os.ReadFile(os.Getenv(config.EnvCAFile))
	if err != nil {
		t.Fatalf("ReadFile(source): %v", err)
	}
	if string(got) != string(src) {
		t.Fatalf("dynamic CA content mismatch")
	}
}

func TestCreateContainerReturnsErrorWhenDynamicCAStagingFailsFailClosed(t *testing.T) {
	source := writeTempSourceCA(t)
	rootFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(rootFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", rootFile, err)
	}
	t.Setenv(config.EnvCAFile, source)
	t.Setenv(config.EnvDynamicCARoot, rootFile)

	p := newPlugin(slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.failPolicy = config.FailPolicyClosed
	pod := &api.PodSandbox{
		Namespace:   "default",
		Name:        "pod-b",
		Annotations: map[string]string{config.AnnoEnabled: "true"},
	}
	ctr := &api.Container{
		Id:   "containerd://efgh5678",
		Name: "app",
		Args: []string{"sh", "-c", "sleep 10"},
	}

	adj, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err == nil {
		t.Fatalf("CreateContainer() should return error when dynamic staging fails")
	}
	if adj != nil {
		t.Fatalf("CreateContainer() adjustment should be nil on error")
	}
}

func TestRemoveContainerCleansDynamicCADirectory(t *testing.T) {
	source := writeTempSourceCA(t)
	root := t.TempDir()
	t.Setenv(config.EnvCAFile, source)
	t.Setenv(config.EnvDynamicCARoot, root)

	p := newPlugin(slog.New(slog.NewTextHandler(io.Discard, nil)))
	pod := &api.PodSandbox{
		Namespace:   "default",
		Name:        "pod-c",
		Annotations: map[string]string{config.AnnoEnabled: "true"},
	}
	ctr := &api.Container{
		Id:   "containerd://ijkl9012",
		Name: "app",
		Args: []string{"sh", "-c", "sleep 10"},
	}

	if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err != nil {
		t.Fatalf("CreateContainer() error = %v", err)
	}
	targetDir, err := containerCADir(root, ctr)
	if err != nil {
		t.Fatalf("containerCADir() error = %v", err)
	}
	if _, err := os.Stat(targetDir); err != nil {
		t.Fatalf("expected staged directory to exist: %v", err)
	}

	if err := p.RemoveContainer(context.Background(), pod, ctr); err != nil {
		t.Fatalf("RemoveContainer() error = %v", err)
	}
	if _, err := os.Stat(targetDir); !os.IsNotExist(err) {
		t.Fatalf("expected staged directory to be removed, stat err=%v", err)
	}
}

func TestCreateContainerReturnsErrorWhenContainerIDEmptyFailClosed(t *testing.T) {
	t.Setenv(config.EnvCAFile, writeTempSourceCA(t))
	t.Setenv(config.EnvDynamicCARoot, t.TempDir())

	p := newPlugin(slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.failPolicy = config.FailPolicyClosed
	pod := &api.PodSandbox{
		Namespace:   "default",
		Name:        "pod-d",
		Annotations: map[string]string{config.AnnoEnabled: "true"},
	}
	ctr := &api.Container{
		Id:   "",
		Name: "app",
		Args: []string{"sh", "-c", "sleep 10"},
	}

	adj, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err == nil {
		t.Fatalf("CreateContainer() should return error when container id is empty")
	}
	if adj != nil {
		t.Fatalf("CreateContainer() adjustment should be nil on error")
	}
	if !strings.Contains(err.Error(), "container id is empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Under fail-open, a staging failure must not fail the container creation.
func TestCreateContainerSkipsInjectionWhenStagingFailsFailOpen(t *testing.T) {
	t.Setenv(config.EnvCAFile, filepath.Join(t.TempDir(), "missing.pem"))
	t.Setenv(config.EnvDynamicCARoot, t.TempDir())

	p := newPlugin(slog.New(slog.NewTextHandler(io.Discard, nil)))
	pod := &api.PodSandbox{Annotations: map[string]string{config.AnnoEnabled: "true"}}
	ctr := &api.Container{Id: "c1", Args: []string{"sh"}}

	adj, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("CreateContainer() error = %v, want nil under fail-open", err)
	}
	if adj != nil {
		t.Fatalf("CreateContainer() should not inject when staging failed")
	}
}

func TestCreateContainerPropagatesPolicyAndTimeout(t *testing.T) {
	t.Setenv(config.EnvCAFile, writeTempSourceCA(t))
	t.Setenv(config.EnvDynamicCARoot, t.TempDir())

	p := newPlugin(slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.failPolicy = config.FailPolicyClosed
	p.hookTimeoutSec = 42
	pod := &api.PodSandbox{Annotations: map[string]string{config.AnnoEnabled: "true"}}
	ctr := &api.Container{Id: "c2", Args: []string{"sh"}}

	adj, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err != nil {
		t.Fatal(err)
	}
	h := adj.GetHooks().GetCreateRuntime()[0]
	if h.GetTimeout().GetValue() != 42 {
		t.Fatalf("hook timeout = %v", h.GetTimeout())
	}
	if envValue(h.GetEnv(), config.EnvFailPolicy) != config.FailPolicyClosed ||
		envValue(h.GetEnv(), config.EnvHookTimeoutSec) != "42" {
		t.Fatalf("hook env = %v", h.GetEnv())
	}
	found := false
	for _, kv := range adj.GetEnv() {
		if kv.GetKey() == config.EnvFailPolicy && kv.GetValue() == config.FailPolicyClosed {
			found = true
		}
	}
	if !found {
		t.Fatalf("container env lacks %s: %v", config.EnvFailPolicy, adj.GetEnv())
	}
}

func writeTempSourceCA(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "source-ca.pem")
	content := "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", p, err)
	}
	return p
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return strings.TrimPrefix(e, prefix)
		}
	}
	return ""
}

func TestUnknownCainjektKeys(t *testing.T) {
	pod := &api.PodSandbox{Annotations: map[string]string{
		config.AnnoEnabled:              "true",
		config.AnnoPrefix + "enable":    "true",
		config.AnnoPrefix + "processor": "x",
		"other.io/enable":               "true",
	}}
	got := unknownCainjektKeys(pod)
	if len(got) != 2 || got[0] != config.AnnoPrefix+"enable" || got[1] != config.AnnoPrefix+"processor" {
		t.Fatalf("unknownCainjektKeys() = %v", got)
	}
}
