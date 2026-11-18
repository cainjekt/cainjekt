package nri

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/stub"
)

// fakeStub fails Run a few times, then blocks until ctx is cancelled.
type fakeStub struct {
	stub.Stub
	fails int32
	runs  atomic.Int32
}

func (f *fakeStub) Run(ctx context.Context) error {
	if f.runs.Add(1) <= f.fails {
		return errors.New("connection refused")
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestRunNRIReconnectsAfterConnectionLoss(t *testing.T) {
	t.Parallel()
	fs := &fakeStub{fails: 3}
	p := &Plugin{stub: fs, log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.runNRI(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for fs.runs.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runNRI returned %v on shutdown, want nil", err)
	}
	if got := fs.runs.Load(); got != 4 {
		t.Fatalf("Run called %d times, want 4 (3 failures + 1 connected)", got)
	}
}
