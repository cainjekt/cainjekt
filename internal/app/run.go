package app

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/cainjekt/cainjekt/internal/config"
	"github.com/cainjekt/cainjekt/internal/install"
	"github.com/cainjekt/cainjekt/internal/nri"
	"github.com/cainjekt/cainjekt/internal/runtime/hook"
	"github.com/cainjekt/cainjekt/internal/runtime/wrapper"
)

func Run(log *slog.Logger, args []string) error {
	if strings.TrimSpace(os.Getenv(config.EnvHookMode)) != "" {
		if err := hook.Run(log); err != nil {
			if strings.EqualFold(getenvOr(config.EnvFailPolicy, config.FailPolicyOpen), config.FailPolicyOpen) {
				log.Error("hook failed (fail-open)", "error", err)
				return nil
			}
			return fmt.Errorf("hook failed: %w", err)
		}
		return nil
	}
	if strings.TrimSpace(os.Getenv(config.EnvWrapperMode)) != "" {
		if err := wrapper.Run(); err != nil {
			return fmt.Errorf("wrapper failed: %w", err)
		}
		return nil
	}

	// Hook and wrapper modes are selected by env and take precedence above:
	// in wrapper mode args are the container's own command line.
	if len(args) > 0 && args[0] == install.Command {
		if err := install.Run(log, args[1:]); err != nil {
			return fmt.Errorf("install failed: %w", err)
		}
		return nil
	}

	if err := nri.Run(log, args); err != nil {
		return fmt.Errorf("plugin failed: %w", err)
	}
	return nil
}

func getenvOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
