// Package wrapper implements the container entrypoint wrapper. It runs as PID 1
// inside the container, applies language-specific CA environment variables
// computed by the hook, and execs the original command.
package wrapper

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/cainjekt/cainjekt/internal/config"
	hookapi "github.com/cainjekt/cainjekt/internal/engine/api"
	"github.com/cainjekt/cainjekt/internal/engine/processors"
	"github.com/cainjekt/cainjekt/internal/runtime/hookctx"
)

// execFunc is replaced in tests.
var execFunc = syscall.Exec

// Run applies wrapper processors and execs os.Args[1:].
//
// Unless the fail policy is explicitly fail-closed, any problem with CA
// injection is logged and the original command is still started: the wrapper
// must never be the reason a workload does not start.
func Run(log *slog.Logger) error {
	if len(os.Args) < 2 {
		return errors.New("wrapper requires original command in argv[1:]")
	}
	return run(log, os.Args[1:])
}

func run(log *slog.Logger, argv []string) error {
	env, err := buildEnv(log)
	if err != nil {
		return err
	}
	return execCommand(argv, env)
}

// buildEnv returns the environment for the original command. It only returns
// an error under the fail-closed policy.
func buildEnv(log *slog.Logger) ([]string, error) {
	original := os.Environ()

	state, err := hookctx.Read()
	if err != nil {
		if config.IsFailClosed(os.Getenv(config.EnvFailPolicy)) {
			return nil, err
		}
		log.Warn("cainjekt: failed to read hook context, starting without language CA settings", "error", err)
		return original, nil
	}
	failClosed := config.IsFailClosed(state.Context.FailPolicy) ||
		(state.Context.FailPolicy == "" && config.IsFailClosed(os.Getenv(config.EnvFailPolicy)))

	ctx := state.ToHookContext()
	ctx.Env = append([]string(nil), original...)
	for _, d := range state.Detected {
		if !d.Applicable {
			continue
		}
		p, ok := processors.ByName(d.Name)
		if !ok {
			continue
		}
		wp, ok := p.(hookapi.WrapperProcessor)
		if !ok {
			continue
		}
		before := append([]string(nil), ctx.Env...)
		if err := wp.ApplyWrapper(ctx); err != nil {
			if failClosed {
				return nil, fmt.Errorf("wrapper processor %q failed: %w", wp.Name(), err)
			}
			log.Warn("cainjekt: wrapper processor failed, skipping", "processor", wp.Name(), "error", err)
			ctx.Env = before
		}
	}
	return ctx.Env, nil
}

func execCommand(argv, env []string) error {
	argv0 := argv[0]
	if !strings.ContainsRune(argv0, '/') {
		// Resolve with the PATH the command will actually run with.
		resolved, err := lookPath(argv0, env)
		if err != nil {
			return fmt.Errorf("failed to resolve command %q: %w", argv0, err)
		}
		argv0 = resolved
	}
	if err := execFunc(argv0, argv, env); err != nil {
		return fmt.Errorf("exec %s failed: %w", argv0, err)
	}
	return nil
}

func lookPath(file string, env []string) (string, error) {
	for i := len(env) - 1; i >= 0; i-- {
		if v, ok := strings.CutPrefix(env[i], "PATH="); ok {
			prev, had := os.LookupEnv("PATH")
			_ = os.Setenv("PATH", v)
			defer func() {
				if had {
					_ = os.Setenv("PATH", prev)
				} else {
					_ = os.Unsetenv("PATH")
				}
			}()
			break
		}
	}
	return exec.LookPath(file)
}
