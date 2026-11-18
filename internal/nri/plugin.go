package nri

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cainjekt/cainjekt/internal/config"
	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
)

type Plugin struct {
	stub    stub.Stub
	log     *slog.Logger
	tracked *tracker
}

// NRI reconnect backoff. A containerd restart drops the connection;
// reconnecting in-process instead of exiting avoids the kubelet's
// CrashLoopBackOff, during which new containers would start without the CA.
// After nriGiveUp without a lasting connection we exit and let the kubelet
// restart the pod, in case the stub itself is wedged.
const (
	nriBackoffMin = 100 * time.Millisecond
	nriBackoffMax = 2 * time.Second
	nriGiveUp     = 2 * time.Minute
	// A Run that lasted at least this long is considered to have connected,
	// which resets the backoff and the give-up timer.
	nriStableConn = 5 * time.Second
)

func Run(log *slog.Logger, args []string) error {
	var (
		pluginName string
		pluginIdx  string
		socketPath string
	)

	fs := flag.NewFlagSet("cainjekt", flag.ContinueOnError)
	fs.StringVar(&pluginName, "name", "", "plugin name to register to NRI")
	fs.StringVar(&pluginIdx, "idx", "", "plugin index to register to NRI")
	fs.StringVar(&socketPath, "socket", "", "path to the plugin socket")
	if err := fs.Parse(args); err != nil {
		return err
	}

	p := newPlugin(log)
	// No WithOnClose: a lost connection makes stub.Run return and runNRI
	// reconnects.
	var opts []stub.Option
	if pluginName != "" {
		opts = append(opts, stub.WithPluginName(pluginName))
	}
	if pluginIdx != "" {
		opts = append(opts, stub.WithPluginIdx(pluginIdx))
	}
	if socketPath != "" {
		opts = append(opts, stub.WithSocketPath(socketPath))
	}

	st, err := stub.New(p, opts...)
	if err != nil {
		return fmt.Errorf("failed to create plugin stub: %w", err)
	}
	p.stub = st

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		st.Stop()
	}()
	go p.runOrphanCleaner(ctx)
	if err := p.runNRI(ctx); err != nil {
		return fmt.Errorf("plugin exited: %w", err)
	}
	p.log.Info("shutting down")
	return nil
}

// runNRI keeps the plugin connected to the runtime until ctx is cancelled.
func (p *Plugin) runNRI(ctx context.Context) error {
	backoff := nriBackoffMin
	failingSince := time.Time{}
	for {
		started := time.Now()
		err := p.stub.Run(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(started) >= nriStableConn || failingSince.IsZero() {
			failingSince = time.Now()
			backoff = nriBackoffMin
		}
		if time.Since(failingSince) > nriGiveUp {
			return fmt.Errorf("no runtime connection for %s: %w", nriGiveUp, err)
		}
		p.log.Warn("connection to runtime lost, reconnecting", "error", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, nriBackoffMax)
	}
}

// Synchronize is called on every (re)connect with all existing containers. It
// rebuilds the tracked set and sweeps directories of containers that are gone.
func (p *Plugin) Synchronize(_ context.Context, pods []*api.PodSandbox, ctrs []*api.Container) ([]*api.ContainerUpdate, error) {
	keys := make([]string, 0, len(ctrs))
	for _, ctr := range ctrs {
		if key, err := containerCAKey(ctr); err == nil {
			keys = append(keys, key)
		}
	}
	p.tracked.reset(keys)
	p.log.Info("synchronized with runtime", "pods", len(pods), "containers", len(ctrs))
	p.sweepOrphans(time.Now())
	return nil, nil
}

func (p *Plugin) PostCreateContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	p.log.Info("post create container", "namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName())
	return nil
}

func (p *Plugin) CreateContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	p.log.Info("create container", "namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName())

	if !shouldInject(pod) {
		return nil, nil, nil
	}

	// Use env var if set (for DaemonSet deployment), otherwise use os.Executable()
	self := getenvOr(config.EnvPluginBinaryPath, "")
	if self == "" {
		var err error
		self, err = os.Executable()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to determine plugin binary path: %w", err)
		}
	}

	sourceCAFile := getenvOr(config.EnvCAFile, config.DefaultCAFile)
	caFileForHook, err := stageDynamicCAFile(sourceCAFile, dynamicCARoot(), ctr)
	if err != nil {
		_ = cleanupDynamicCAFile(dynamicCARoot(), ctr)
		return nil, nil, err
	}
	if key, err := containerCAKey(ctr); err == nil {
		p.tracked.add(key)
	}

	hook := &api.Hook{
		Path: self,
		Env: []string{
			config.EnvHookMode + "=" + config.ModeCreateRT,
			config.EnvCAFile + "=" + caFileForHook,
			config.EnvFailPolicy + "=" + config.FailPolicyOpen,
			config.EnvHookContextFile + "=" + config.HookContextFile,
		},
		Timeout: api.Int(config.DefaultHookTimeoutSec),
	}

	adjustment := &api.ContainerAdjustment{}
	adjustment.AddEnv(config.EnvWrapperMode, "1")
	if !hasEnv(ctr.GetEnv(), config.EnvHookContextFile) {
		adjustment.AddEnv(config.EnvHookContextFile, config.HookContextFile)
	}
	if args := ctr.GetArgs(); len(args) > 0 && args[0] != config.WrapperPath {
		adjustment.UpdateArgs(append([]string{config.WrapperPath}, args...))
	}
	adjustment.AddMount(&api.Mount{
		Destination: config.WrapperPath,
		Type:        "bind",
		Source:      self,
		Options:     []string{"bind", "ro"},
	})
	adjustment.AddHooks(&api.Hooks{CreateRuntime: []*api.Hook{hook}})
	return adjustment, nil, nil
}

func (p *Plugin) RemoveContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	p.log.Info("removed container", "namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName())
	if key, err := containerCAKey(ctr); err == nil {
		p.tracked.remove(key)
	}
	if !shouldInject(pod) {
		return nil
	}
	if err := cleanupDynamicCAFile(dynamicCARoot(), ctr); err != nil {
		p.log.Warn("failed to cleanup dynamic CA bundle", "error", err)
	}
	return nil
}
