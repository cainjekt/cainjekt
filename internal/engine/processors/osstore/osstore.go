// Package osstore provides processors that add the CA to the distribution
// trust store of the container image (Debian, RHEL, openSUSE, Alpine, Arch,
// and a generic fallback).
package osstore

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	hookapi "github.com/cainjekt/cainjekt/internal/engine/api"
	"github.com/cainjekt/cainjekt/internal/util/containerfs"
	"github.com/cainjekt/cainjekt/pkg/certs"
)

const individualCAFileName = "cainjekt.crt"

type processor struct {
	name       string
	distro     string
	candidates []string
	anchorDir  string
	matchIDs   []string
	priority   int
	fallback   bool
}

// NewDebian returns the processor for Debian and Ubuntu images.
func NewDebian() hookapi.Processor {
	return &processor{
		name:       "os-debian",
		distro:     "debian",
		candidates: []string{"/etc/ssl/certs/ca-certificates.crt"},
		anchorDir:  "/usr/local/share/ca-certificates",
		matchIDs:   []string{"debian", "ubuntu"},
		priority:   300,
	}
}

// NewRHEL returns the processor for RHEL-family images (Fedora, CentOS,
// Rocky, AlmaLinux, Oracle Linux, Amazon Linux).
func NewRHEL() hookapi.Processor {
	return &processor{
		name:       "os-rhel",
		distro:     "rhel",
		candidates: []string{"/etc/pki/tls/certs/ca-bundle.crt"},
		anchorDir:  "/etc/pki/ca-trust/source/anchors",
		matchIDs:   []string{"rhel", "fedora", "centos", "rocky", "almalinux", "ol", "amzn"},
		priority:   290,
	}
}

// NewOpenSUSE returns the processor for openSUSE and SLES images.
func NewOpenSUSE() hookapi.Processor {
	return &processor{
		name:       "os-opensuse",
		distro:     "opensuse",
		candidates: []string{"/etc/ssl/ca-bundle.pem"},
		anchorDir:  "/etc/pki/trust/anchors",
		matchIDs:   []string{"opensuse", "sles", "suse"},
		priority:   285,
	}
}

// NewAlpine returns the processor for Alpine images.
func NewAlpine() hookapi.Processor {
	return &processor{
		name:       "os-alpine",
		distro:     "alpine",
		candidates: []string{"/etc/ssl/certs/ca-certificates.crt"},
		anchorDir:  "/usr/local/share/ca-certificates",
		matchIDs:   []string{"alpine"},
		priority:   280,
	}
}

// NewArch returns the processor for Arch Linux images.
func NewArch() hookapi.Processor {
	return &processor{
		name:       "os-arch",
		distro:     "arch",
		candidates: []string{"/etc/ssl/certs/ca-certificates.crt"},
		anchorDir:  "/etc/ca-certificates/trust-source/anchors",
		matchIDs:   []string{"arch"},
		priority:   275,
	}
}

// NewFallback returns the lowest-priority processor, used when the
// distribution is unknown or unsupported; it targets the first well-known
// bundle path found.
func NewFallback() hookapi.Processor {
	return &processor{
		name:   "os-fallback",
		distro: "fallback",
		candidates: []string{
			"/etc/ssl/certs/ca-certificates.crt",
			"/etc/pki/tls/certs/ca-bundle.crt",
			"/etc/ssl/ca-bundle.pem",
			"/etc/ssl/cert.pem",
		},
		priority: -100,
		fallback: true,
	}
}

func (p *processor) Name() string { return p.name }

func (p *processor) Category() string { return "os" }

func (p *processor) Detect(ctx *hookapi.Context) hookapi.DetectResult {
	if ctx == nil {
		return hookapi.DetectResult{Applicable: false, Priority: p.priority, Reason: "missing context"}
	}
	info, err := readOSRelease(ctx.Rootfs)
	if err != nil {
		if p.fallback {
			return hookapi.DetectResult{Applicable: true, Priority: p.priority, Reason: "fallback: os-release not found"}
		}
		return hookapi.DetectResult{Applicable: false, Priority: p.priority, Reason: err.Error()}
	}
	if p.matches(info) {
		return hookapi.DetectResult{Applicable: true, Priority: p.priority}
	}
	if p.fallback {
		return hookapi.DetectResult{Applicable: true, Priority: p.priority, Reason: "fallback: unsupported distro"}
	}
	return hookapi.DetectResult{
		Applicable: false,
		Priority:   p.priority,
		Reason:     fmt.Sprintf("distro mismatch: id=%q id_like=%q", info.id, strings.Join(info.idLike, " ")),
	}
}

func (p *processor) Apply(ctx *hookapi.Context) error {
	if trustStoreConfigured(ctx) {
		return nil
	}

	orgCA, err := ctx.ReadCABundle()
	if err != nil {
		return err
	}

	target := detectTrustStorePath(ctx.Rootfs, p.candidates)
	if target == "" {
		return errors.New("no known trust store path found in rootfs")
	}

	current, resolved, err := containerfs.ReadFile(ctx.Rootfs, target)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to read trust store %s: %w", target, err)
	}

	merged, err := certs.MergePEM(current, orgCA)
	if err != nil {
		return err
	}

	if merged.Added > 0 {
		if _, err := containerfs.WriteFile(ctx.Rootfs, resolved, merged.Merged, 0o644); err != nil {
			return fmt.Errorf("failed to write trust store: %w", err)
		}
		// Alpine images often use /etc/ssl/cert.pem as curl/OpenSSL default.
		if p.distro == "alpine" {
			if err := writeAlpineCertPEM(ctx.Rootfs, resolved, merged.Merged); err != nil {
				return err
			}
		}
	}

	individualCAPath, err := writeIndividualCA(ctx.Rootfs, p.anchorDir, orgCA)
	if err != nil {
		return err
	}

	ctx.Facts.Set(hookapi.FactTrustStorePath, resolved)
	ctx.Facts.Set(hookapi.FactTrustStoreKind, "bundle")
	ctx.Facts.Set(hookapi.FactDistro, p.distro)
	if individualCAPath != "" {
		ctx.Facts.Set(hookapi.FactIndividualCAPath, individualCAPath)
	}
	return nil
}

// writeAlpineCertPEM keeps /etc/ssl/cert.pem in sync with the merged bundle.
// On Alpine it is usually a symlink to the main bundle; then there is nothing
// to do.
func writeAlpineCertPEM(rootfs, mainBundle string, merged []byte) error {
	const alpineCertPEM = "/etc/ssl/cert.pem"
	resolved, err := containerfs.ResolveSymlinks(rootfs, alpineCertPEM)
	if err != nil {
		return fmt.Errorf("failed to resolve alpine cert path %s: %w", alpineCertPEM, err)
	}
	if resolved == mainBundle {
		return nil
	}
	if _, err := containerfs.WriteFile(rootfs, resolved, merged, 0o644); err != nil {
		return fmt.Errorf("failed to write alpine default cert path: %w", err)
	}
	return nil
}

func trustStoreConfigured(ctx *hookapi.Context) bool {
	if ctx == nil || ctx.Facts == nil {
		return false
	}
	v, ok := ctx.Facts.Get(hookapi.FactTrustStorePath)
	return ok && strings.TrimSpace(v) != ""
}

// detectTrustStorePath returns the first candidate that is a regular file in
// the rootfs, or the first candidate if none exists yet.
func detectTrustStorePath(rootfs string, candidates []string) string {
	for _, c := range candidates {
		if _, ok := containerfs.RegularFile(rootfs, c); ok {
			return c
		}
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return ""
}

type osRelease struct {
	id     string
	idLike []string
}

func readOSRelease(rootfs string) (osRelease, error) {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		data, _, err := containerfs.ReadFile(rootfs, p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return osRelease{}, fmt.Errorf("failed to read os-release %s: %w", p, err)
		}
		info, err := parseOSRelease(bytes.NewReader(data))
		if err != nil {
			return osRelease{}, fmt.Errorf("failed to parse os-release %s: %w", p, err)
		}
		if info.id == "" {
			return osRelease{}, fmt.Errorf("os-release %s has empty ID", p)
		}
		return info, nil
	}
	return osRelease{}, errors.New("os-release not found")
}

func parseOSRelease(r io.Reader) (osRelease, error) {
	var out osRelease
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := strings.TrimSpace(k)
		val := normalizeOSReleaseValue(strings.TrimSpace(v))
		switch key {
		case "ID":
			out.id = strings.ToLower(val)
		case "ID_LIKE":
			out.idLike = append(out.idLike, strings.Fields(strings.ToLower(val))...)
		}
	}
	if err := sc.Err(); err != nil {
		return osRelease{}, err
	}
	return out, nil
}

func normalizeOSReleaseValue(v string) string {
	if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
		v = v[1 : len(v)-1]
	}
	return strings.TrimSpace(v)
}

func writeIndividualCA(rootfs, anchorDir string, content []byte) (string, error) {
	if anchorDir == "" {
		return "", nil
	}
	target := path.Join(anchorDir, individualCAFileName)
	resolved, err := containerfs.WriteFile(rootfs, target, content, 0o644)
	if err != nil {
		return "", fmt.Errorf("failed to write individual CA file %s: %w", target, err)
	}
	return resolved, nil
}

func (p *processor) matches(info osRelease) bool {
	ids := map[string]struct{}{}
	if info.id != "" {
		ids[info.id] = struct{}{}
	}
	for _, like := range info.idLike {
		if like != "" {
			ids[like] = struct{}{}
		}
	}
	for _, id := range p.matchIDs {
		if _, ok := ids[id]; ok {
			return true
		}
	}
	return false
}
