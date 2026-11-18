package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	EnvHookMode   = "HOOK_MODE"
	ModeCreateRT  = "createruntime"
	ModeCreateCtr = "createcontainer"

	EnvCAFile           = "CAINJEKT_CA_FILE"
	EnvDynamicCARoot    = "CAINJEKT_DYNAMIC_CA_ROOT"
	EnvFailPolicy       = "CAINJEKT_FAIL_POLICY"
	EnvWrapperMode      = "CAINJEKT_WRAPPER_MODE"
	EnvHookContextFile  = "CAINJEKT_HOOK_CONTEXT_FILE"
	EnvPluginBinaryPath = "CAINJEKT_PLUGIN_BINARY_PATH"
	EnvHookTimeoutSec   = "CAINJEKT_HOOK_TIMEOUT_SEC"

	AnnoEnabled = "cainjekt.tsuzu.dev/enabled"

	AnnoProcessorsInclude = "cainjekt.tsuzu.dev/processors.include"
	AnnoProcessorsExclude = "cainjekt.tsuzu.dev/processors.exclude"

	FailPolicyOpen          = "fail-open"
	FailPolicyClosed        = "fail-closed"
	DefaultCAFile           = "/etc/cainjekt/ca-bundle.pem"
	DefaultDynamicCARoot    = "/run/cainjekt/containers"
	DefaultMode             = "fs"
	WrapperPath             = "/cainjekt-entrypoint"
	HookContextFile         = "/etc/cainjekt/hook-context.json"
	DefaultPluginBinaryPath = "/opt/cainjekt/bin/cainjekt"

	// The runtime SIGKILLs a hook that exceeds its timeout and then FAILS the
	// container creation, regardless of the fail policy. update-ca-certificates
	// style work on busy nodes can take several seconds, so be generous; the
	// hook gives up on its own one second before the deadline (see
	// HookBudget) so fail-open is honored.
	DefaultHookTimeoutSec = 20
	MinHookTimeoutSec     = 2
	MaxHookTimeoutSec     = 120
)

// IsFailClosed reports whether policy explicitly requests fail-closed
// behavior. Anything else, including an empty or unknown value, is fail-open:
// a CA injection problem must not take workloads down unless asked to.
func IsFailClosed(policy string) bool {
	return strings.EqualFold(strings.TrimSpace(policy), FailPolicyClosed)
}

// ParseFailPolicy validates a fail policy value. Empty means fail-open.
func ParseFailPolicy(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", FailPolicyOpen:
		return FailPolicyOpen, nil
	case FailPolicyClosed:
		return FailPolicyClosed, nil
	default:
		return "", fmt.Errorf("invalid %s %q: must be %q or %q", EnvFailPolicy, v, FailPolicyOpen, FailPolicyClosed)
	}
}

// ParseHookTimeoutSec validates the OCI hook timeout in seconds. Empty means
// DefaultHookTimeoutSec.
func ParseHookTimeoutSec(v string) (int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return DefaultHookTimeoutSec, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < MinHookTimeoutSec || n > MaxHookTimeoutSec {
		return 0, fmt.Errorf("invalid %s %q: must be an integer between %d and %d", EnvHookTimeoutSec, v, MinHookTimeoutSec, MaxHookTimeoutSec)
	}
	return n, nil
}

// HookBudget is how long the hook may work before giving up by itself, so it
// exits before the runtime kills it.
func HookBudget(timeoutSec int) time.Duration {
	return time.Duration(max(timeoutSec-1, 1)) * time.Second
}
