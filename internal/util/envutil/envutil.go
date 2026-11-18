package envutil

import "strings"

func Upsert(env []string, key, value string) []string {
	prefix := key + "="
	entry := prefix + value
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = entry
			return env
		}
	}
	return append(env, entry)
}

// GetValue returns the value for key from an env slice, or "" if not found.
func GetValue(env []string, key string) string {
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return strings.TrimPrefix(e, prefix)
		}
	}
	return ""
}
