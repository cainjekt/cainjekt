package api

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cainjekt/cainjekt/pkg/fsx"
)

type FactKey string

const (
	FactTrustStorePath   FactKey = "trust_store_path"
	FactTrustStoreKind   FactKey = "trust_store_kind"
	FactDistro           FactKey = "distro"
	FactIndividualCAPath FactKey = "individual_ca_path"
)

type DetectResult struct {
	Applicable bool
	Reason     string
	Priority   int
}

type Processor interface {
	Name() string
	Category() string
	Detect(*Context) DetectResult
	Apply(*Context) error
}

// WrapperProcessor extends Processor with wrapper-runtime handling.
type WrapperProcessor interface {
	Processor
	ApplyWrapper(*Context) error
}

type ProcessorResult struct {
	Name     string
	Category string
	Applied  bool
	Skipped  bool
	Err      error
	Reason   string
}

type FactStore interface {
	Set(FactKey, string)
	Get(FactKey) (string, bool)
	Snapshot() map[FactKey]string
}

type MapFactStore struct {
	values map[FactKey]string
}

func NewMapFactStore() *MapFactStore {
	return &MapFactStore{values: map[FactKey]string{}}
}

func (s *MapFactStore) Set(key FactKey, value string) {
	s.values[key] = value
}

func (s *MapFactStore) Get(key FactKey) (string, bool) {
	v, ok := s.values[key]
	return v, ok
}

func (s *MapFactStore) Snapshot() map[FactKey]string {
	out := make(map[FactKey]string, len(s.values))
	for k, v := range s.values {
		out[k] = v
	}
	return out
}

func NewMapFactStoreFromSnapshot(values map[FactKey]string) *MapFactStore {
	out := NewMapFactStore()
	for k, v := range values {
		out.values[k] = v
	}
	return out
}

type Context struct {
	Mode        string
	Bundle      string
	Annotations map[string]string
	Rootfs      string
	CAFile      string
	// ContainerCADir is the container path where the NRI plugin mounted the
	// staged CA directory (the directory of CAFile), or "" if not mounted.
	ContainerCADir string
	FailPolicy     string
	Env            []string

	Facts   FactStore
	Results []ProcessorResult
}

func (c *Context) AddResult(r ProcessorResult) {
	c.Results = append(c.Results, r)
}

// ReadCABundle reads the organization CA bundle staged by the NRI plugin. It
// is a plugin-owned host path, not part of the (untrusted) container rootfs.
func (c *Context) ReadCABundle() ([]byte, error) {
	b, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA bundle file %s: %w", c.CAFile, err)
	}
	return b, nil
}

// StageFile atomically writes name into the plugin-owned staging directory
// (the directory of CAFile on the host). When ContainerCADir is set, the file
// is visible to the container at ContainerCADir/name.
func (c *Context) StageFile(name string, data []byte) error {
	if c.CAFile == "" || name == "" || filepath.Base(name) != name {
		return fmt.Errorf("invalid staged file %q", name)
	}
	target := filepath.Join(filepath.Dir(c.CAFile), name)
	if err := fsx.AtomicWrite(target, data, fsx.WriteOptions{FallbackMode: 0o644, RefuseSymlink: true}); err != nil {
		return fmt.Errorf("failed to stage %s: %w", target, err)
	}
	return nil
}
