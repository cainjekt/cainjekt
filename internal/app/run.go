package app

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/cainjekt/cainjekt/internal/config"
	"github.com/cainjekt/cainjekt/internal/nri"
	"github.com/cainjekt/cainjekt/internal/runtime/hook"
	"github.com/cainjekt/cainjekt/internal/runtime/wrapper"
)

func Run(log *slog.Logger, args []string) error {
	if strings.TrimSpace(os.Getenv(config.EnvHookMode)) != "" {
		if err := hook.Run(log); err != nil {
			if config.IsFailClosed(os.Getenv(config.EnvFailPolicy)) {
				return fmt.Errorf("hook failed: %w", err)
			}
			log.Error("hook failed (fail-open)", "error", err)
			return nil
		}
		return nil
	}
	if strings.TrimSpace(os.Getenv(config.EnvWrapperMode)) != "" {
		if err := wrapper.Run(log); err != nil {
			return fmt.Errorf("wrapper failed: %w", err)
		}
		return nil
	}

	if err := nri.Run(log, args); err != nil {
		return fmt.Errorf("plugin failed: %w", err)
	}
	return nil
}
