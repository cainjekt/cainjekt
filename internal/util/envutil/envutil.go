// Package envutil manipulates KEY=VALUE environment lists.
package envutil

import "strings"

// Upsert sets key to value in env, replacing the first existing entry for key
// in place or appending a new one, and returns the updated slice.
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
