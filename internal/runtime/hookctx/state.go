package hookctx

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/cainjekt/cainjekt/internal/config"
	hookapi "github.com/cainjekt/cainjekt/internal/engine/api"
	"github.com/cainjekt/cainjekt/internal/util/containerfs"
)

type DetectedProcessor struct {
	Name       string `json:"name"`
	Category   string `json:"category"`
	Applicable bool   `json:"applicable"`
	Priority   int    `json:"priority"`
	Reason     string `json:"reason,omitempty"`
}

// PersistedContext is the subset of the hook context the wrapper needs.
//
// The file lives inside the container rootfs and is readable by the workload,
// so it must only contain what the wrapper uses: never pod annotations (which
// can carry kubectl last-applied configs or other sensitive data) nor host
// paths such as the bundle directory.
type PersistedContext struct {
	FailPolicy string            `json:"fail_policy,omitempty"`
	Facts      map[string]string `json:"facts,omitempty"`
}

type State struct {
	Context  PersistedContext    `json:"context"`
	Detected []DetectedProcessor `json:"detected,omitempty"`
}

func NewStateFromContext(ctx *hookapi.Context, detected []DetectedProcessor) State {
	facts := map[string]string{}
	for k, v := range ctx.Facts.Snapshot() {
		facts[string(k)] = v
	}
	// The wrapper only acts on applicable processors; reasons may contain
	// host-side error details.
	applicable := make([]DetectedProcessor, 0, len(detected))
	for _, d := range detected {
		if d.Applicable {
			d.Reason = ""
			applicable = append(applicable, d)
		}
	}
	return State{
		Context: PersistedContext{
			FailPolicy: ctx.FailPolicy,
			Facts:      facts,
		},
		Detected: applicable,
	}
}

func (s State) ToHookContext() *hookapi.Context {
	facts := map[hookapi.FactKey]string{}
	for k, v := range s.Context.Facts {
		facts[hookapi.FactKey(k)] = v
	}
	return &hookapi.Context{
		Annotations: map[string]string{},
		FailPolicy:  s.Context.FailPolicy,
		Facts:       hookapi.NewMapFactStoreFromSnapshot(facts),
	}
}

// Write persists the wrapper state inside the container rootfs. The rootfs is
// untrusted, so the write is confined with containerfs: a symlinked
// /etc/cainjekt in the image can never redirect it to the host.
func Write(rootfs string, state State) error {
	b, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal hook context: %w", err)
	}
	if _, err := containerfs.WriteFile(rootfs, contextFilePath(), append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("failed to write hook context file: %w", err)
	}
	return nil
}

func Read() (State, error) {
	p := contextFilePath()
	// Read runs inside the container (wrapper), on its own filesystem.
	b, err := os.ReadFile(p) //nolint:forbidigo // not hook-phase: runs in the container
	if err != nil {
		if os.IsNotExist(err) {
			return State{}, nil
		}
		return State{}, fmt.Errorf("failed to read hook context file %s: %w", p, err)
	}
	var out State
	if err := json.Unmarshal(b, &out); err != nil {
		return State{}, fmt.Errorf("failed to parse hook context file %s: %w", p, err)
	}
	out.Context.Facts = cloneStringMap(out.Context.Facts)
	return out, nil
}

func contextFilePath() string {
	if p := strings.TrimSpace(os.Getenv(config.EnvHookContextFile)); p != "" {
		return p
	}
	// Backward compatibility for existing deployments.
	if p := strings.TrimSpace(os.Getenv("CAINJEKT_WRAPPER_CONTEXT_FILE")); p != "" {
		return p
	}
	return config.HookContextFile
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
