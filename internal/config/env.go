package config

import (
	"os"
	"strings"
)

// GetenvOr returns the value of the environment variable key with surrounding
// whitespace trimmed, or fallback if it is unset or blank.
func GetenvOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
