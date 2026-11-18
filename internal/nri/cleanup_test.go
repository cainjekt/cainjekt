package nri

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cainjekt/cainjekt/internal/config"
	"github.com/containerd/nri/pkg/api"
)

func mkStaged(t *testing.T, root, id string, age time.Duration) string {
	t.Helper()
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-age)
	if err := os.Chtimes(dir, old, old); err != nil {
		t.Fatal(err)
	}
	return dir
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func TestSynchronizeRemovesDirsOfVanishedContainersOnly(t *testing.T) {
	root := t.TempDir()
	t.Setenv(config.EnvDynamicCARoot, root)
	p := newPlugin(slog.New(slog.NewTextHandler(io.Discard, nil)))

	running := mkStaged(t, root, "running", time.Hour)
	gone := mkStaged(t, root, "gone", time.Hour)
	fresh := mkStaged(t, root, "fresh", time.Second) // CreateContainer may be in flight

	if _, err := p.Synchronize(context.Background(), nil, []*api.Container{{Id: "running"}}); err != nil {
		t.Fatal(err)
	}
	if !exists(running) {
		t.Fatal("staged dir of a running container was removed")
	}
	if exists(gone) {
		t.Fatal("staged dir of a vanished container was kept")
	}
	if !exists(fresh) {
		t.Fatal("recently staged dir was removed")
	}
}

func TestTrackedSetFollowsCreateAndRemove(t *testing.T) {
	t.Setenv(config.EnvCAFile, writeTempSourceCA(t))
	root := t.TempDir()
	t.Setenv(config.EnvDynamicCARoot, root)
	p := newPlugin(slog.New(slog.NewTextHandler(io.Discard, nil)))
	pod := &api.PodSandbox{Annotations: map[string]string{config.AnnoEnabled: "true"}}
	ctr := &api.Container{Id: "c1", Args: []string{"sh"}}

	if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err != nil {
		t.Fatal(err)
	}
	if !p.tracked.has("c1") {
		t.Fatal("created container not tracked")
	}
	// Tracked containers survive a sweep even when their dir is old.
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(filepath.Join(root, "c1"), old, old)
	if p.sweepOrphans(time.Now()) != 0 || !exists(filepath.Join(root, "c1")) {
		t.Fatal("tracked container dir was swept")
	}
	if err := p.RemoveContainer(context.Background(), pod, ctr); err != nil {
		t.Fatal(err)
	}
	if p.tracked.has("c1") || exists(filepath.Join(root, "c1")) {
		t.Fatal("removed container still tracked or staged")
	}
}
