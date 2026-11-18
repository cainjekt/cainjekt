// Package api defines the types shared by the hook engine and its processors.
package api

import (
	"fmt"
	"os"
)

// FactKey names a fact processors share through a FactStore.
type FactKey string

// Well-known fact keys.
const (
	FactTrustStorePath   FactKey = "trust_store_path"
	FactTrustStoreKind   FactKey = "trust_store_kind"
	FactDistro           FactKey = "distro"
	FactIndividualCAPath FactKey = "individual_ca_path"
)

// DetectResult reports whether a processor applies to a container and, if
// so, with which priority (higher runs first).
type DetectResult struct {
	Applicable bool
	Reason     string
	Priority   int
}

// Processor detects a runtime or trust store in the container and injects the
// CA into it.
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

// ProcessorResult records the outcome of one processor.
type ProcessorResult struct {
	Name     string
	Category string
	Applied  bool
	Skipped  bool
	Err      error
	Reason   string
}

// FactStore holds facts discovered by processors for later ones.
type FactStore interface {
	Set(FactKey, string)
	Get(FactKey) (string, bool)
	Snapshot() map[FactKey]string
}

// MapFactStore is a map-backed FactStore.
type MapFactStore struct {
	values map[FactKey]string
}

// NewMapFactStore returns an empty MapFactStore.
func NewMapFactStore() *MapFactStore {
	return &MapFactStore{values: map[FactKey]string{}}
}

// Set stores value under key.
func (s *MapFactStore) Set(key FactKey, value string) {
	s.values[key] = value
}

// Get returns the value stored under key.
func (s *MapFactStore) Get(key FactKey) (string, bool) {
	v, ok := s.values[key]
	return v, ok
}

// Snapshot returns a copy of all stored facts.
func (s *MapFactStore) Snapshot() map[FactKey]string {
	out := make(map[FactKey]string, len(s.values))
	for k, v := range s.values {
		out[k] = v
	}
	return out
}

// NewMapFactStoreFromSnapshot returns a MapFactStore holding a copy of values.
func NewMapFactStoreFromSnapshot(values map[FactKey]string) *MapFactStore {
	out := NewMapFactStore()
	for k, v := range values {
		out.values[k] = v
	}
	return out
}

// Context carries the container being processed and the accumulated facts
// and results through the processors of a hook or wrapper run.
type Context struct {
	Mode        string
	Bundle      string
	Annotations map[string]string
	Rootfs      string
	CAFile      string
	FailPolicy  string
	Env         []string

	Facts   FactStore
	Results []ProcessorResult
}

// AddResult appends r to Results.
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
