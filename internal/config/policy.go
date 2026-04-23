package config

import "strings"

type InjectionPolicy string

func NormalizeInjectionPolicy(policy string) InjectionPolicy {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case string(InjectionPolicyOptOut):
		return InjectionPolicyOptOut
	default:
		return DefaultInjectionPolicy
	}
}

func ParseInjectionPolicy(policy string) (InjectionPolicy, bool) {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case string(InjectionPolicyOptIn):
		return InjectionPolicyOptIn, true
	case string(InjectionPolicyOptOut):
		return InjectionPolicyOptOut, true
	default:
		return "", false
	}
}
