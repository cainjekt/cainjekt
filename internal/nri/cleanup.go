package nri

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	orphanSweepInterval = 10 * time.Minute
	// A staged directory younger than this is never removed: it may belong to
	// a container whose CreateContainer is still in flight.
	orphanMinAge = 10 * time.Minute
)

// tracker records the containers that currently have a staged CA directory.
//
// It is rebuilt from the runtime's container list on every Synchronize (plugin
// start and every reconnect), so RemoveContainer events missed while the plugin
// was down or disconnected do not leak directories forever.
type tracker struct {
	mu  sync.Mutex
	ids map[string]struct{}
}

func newTracker() *tracker {
	return &tracker{ids: map[string]struct{}{}}
}

func (t *tracker) add(key string) {
	t.mu.Lock()
	t.ids[key] = struct{}{}
	t.mu.Unlock()
}

func (t *tracker) remove(key string) {
	t.mu.Lock()
	delete(t.ids, key)
	t.mu.Unlock()
}

func (t *tracker) reset(keys []string) {
	ids := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		ids[k] = struct{}{}
	}
	t.mu.Lock()
	t.ids = ids
	t.mu.Unlock()
}

func (t *tracker) has(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.ids[key]
	return ok
}

// sweepOrphans removes staged CA directories of containers that are not
// tracked and older than orphanMinAge. It returns the number removed.
func (p *Plugin) sweepOrphans(now time.Time) int {
	root := dynamicCARoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		if !os.IsNotExist(err) {
			p.log.Warn("orphan cleanup: failed to read dynamic CA root", "root", root, "error", err)
		}
		return 0
	}
	removed := 0
	for _, e := range entries {
		if !e.IsDir() || p.tracked.has(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil || now.Sub(info.ModTime()) < orphanMinAge {
			continue
		}
		dir := filepath.Join(root, e.Name())
		if err := os.RemoveAll(dir); err != nil {
			p.log.Warn("orphan cleanup: failed to remove", "dir", dir, "error", err)
			continue
		}
		removed++
	}
	if removed > 0 {
		p.log.Info("orphan cleanup: removed stale CA directories", "count", removed)
	}
	return removed
}

func (p *Plugin) runOrphanCleaner(ctx context.Context) {
	t := time.NewTicker(orphanSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			p.sweepOrphans(now)
		}
	}
}
