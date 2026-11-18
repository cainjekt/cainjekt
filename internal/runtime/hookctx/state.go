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

type PersistedContext struct {
	Mode        string            `json:"mode,omitempty"`
	Bundle      string            `json:"bundle,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	CAFile      string            `json:"ca_file,omitempty"`
	FailPolicy  string            `json:"fail_policy,omitempty"`
	Facts       map[string]string `json:"facts,omitempty"`
}

type State struct {
	Context  PersistedContext    `json:"context"`
	Detected []DetectedProcessor `json:"detected,omitempty"`
}

func NewStateFromContext(ctx *hookapi.Context, detected []DetectedProcessor) State {
	ann := make(map[string]string, len(ctx.Annotations))
	for k, v := range ctx.Annotations {
		ann[k] = v
	}
	facts := map[string]string{}
	for k, v := range ctx.Facts.Snapshot() {
		facts[string(k)] = v
	}
	return State{
		Context: PersistedContext{
			Mode:        ctx.Mode,
			Bundle:      ctx.Bundle,
			Annotations: ann,
			CAFile:      ctx.CAFile,
			FailPolicy:  ctx.FailPolicy,
			Facts:       facts,
		},
		Detected: detected,
	}
}

func (s State) ToHookContext() *hookapi.Context {
	facts := map[hookapi.FactKey]string{}
	for k, v := range s.Context.Facts {
		facts[hookapi.FactKey(k)] = v
	}
	return &hookapi.Context{
		Mode:        s.Context.Mode,
		Bundle:      s.Context.Bundle,
		Annotations: cloneStringMap(s.Context.Annotations),
		CAFile:      s.Context.CAFile,
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
	out.Context.Annotations = cloneStringMap(out.Context.Annotations)
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
