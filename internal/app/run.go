package app

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/cainjekt/cainjekt/internal/config"
	"github.com/cainjekt/cainjekt/internal/nri"
	"github.com/cainjekt/cainjekt/internal/runtime/hook"
	"github.com/cainjekt/cainjekt/internal/runtime/wrapper"
)

func Run(log *slog.Logger, args []string) error {
	if strings.TrimSpace(os.Getenv(config.EnvHookMode)) != "" {
		return runHook(log)
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

// runHook runs the OCI hook within a budget slightly below the runtime's hook
// timeout. The runtime SIGKILLs a hook that overruns and then fails the
// container regardless of the fail policy, so under fail-open the hook gives
// up on its own and lets the container start. File writes are atomic
// (temp file + rename), so abandoning in-flight work cannot leave a truncated
// trust store behind.
func runHook(log *slog.Logger) error {
	failClosed := config.IsFailClosed(os.Getenv(config.EnvFailPolicy))
	timeoutSec, err := config.ParseHookTimeoutSec(os.Getenv(config.EnvHookTimeoutSec))
	if err != nil {
		timeoutSec = config.DefaultHookTimeoutSec
	}
	budget := config.HookBudget(timeoutSec)

	done := make(chan error, 1)
	run := hookRun // read once: an abandoned goroutine must not race on it
	go func() { done <- run(log) }()

	select {
	case err = <-done:
	case <-time.After(budget):
		err = fmt.Errorf("hook did not finish within %s (runtime timeout %ds)", budget, timeoutSec)
	}
	if err == nil {
		return nil
	}
	if failClosed {
		return fmt.Errorf("hook failed: %w", err)
	}
	log.Error("hook failed (fail-open)", "error", err)
	return nil
}

// hookRun is replaced in tests.
var hookRun = hook.Run
