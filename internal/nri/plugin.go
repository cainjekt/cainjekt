package nri

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
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
	metrics *metrics
	// ready is true while connected to and synchronized with the runtime:
	// set in Synchronize, cleared when stub.Run returns.
	ready atomic.Bool

	failPolicy     string
	hookTimeoutSec int
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
		httpAddr   string
	)

	fs := flag.NewFlagSet("cainjekt", flag.ContinueOnError)
	fs.StringVar(&pluginName, "name", "", "plugin name to register to NRI")
	fs.StringVar(&pluginIdx, "idx", "", "plugin index to register to NRI")
	fs.StringVar(&socketPath, "socket", "", "path to the plugin socket")
	fs.StringVar(&httpAddr, "http-addr", defaultHTTPAddr,
		"listen address for /healthz, /readyz and /metrics (empty disables the server)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	p := newPlugin(log)
	var err error
	if p.failPolicy, err = config.ParseFailPolicy(os.Getenv(config.EnvFailPolicy)); err != nil {
		return err
	}
	if p.hookTimeoutSec, err = config.ParseHookTimeoutSec(os.Getenv(config.EnvHookTimeoutSec)); err != nil {
		return err
	}
	log.Info("starting", "fail_policy", p.failPolicy, "hook_timeout_sec", p.hookTimeoutSec)
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

	var httpDone chan struct{}
	if httpAddr != "" {
		ln, err := net.Listen("tcp", httpAddr)
		if err != nil {
			return fmt.Errorf("failed to listen on --http-addr %s: %w", httpAddr, err)
		}
		log.Info("serving health and metrics", "addr", ln.Addr().String())
		httpDone = make(chan struct{})
		go func() {
			defer close(httpDone)
			serveHTTP(ctx, log, newHTTPServer(p.metrics.registry, p.ready.Load), ln)
		}()
	}

	go p.runOrphanCleaner(ctx)
	go p.runCAMetricsRefresher(ctx, getenvOr(config.EnvCAFile, config.DefaultCAFile))
	err = p.runNRI(ctx)
	// Stop the HTTP server on give-up too, and wait for it to drain.
	stop()
	if httpDone != nil {
		<-httpDone
	}
	if err != nil {
		return fmt.Errorf("plugin exited: %w", err)
	}
	p.log.Info("shutting down")
	return nil
}

func (p *Plugin) setReady(ready bool) {
	p.ready.Store(ready)
	if ready {
		p.metrics.nriConnected.Set(1)
	} else {
		p.metrics.nriConnected.Set(0)
	}
}

// runNRI keeps the plugin connected to the runtime until ctx is cancelled.
func (p *Plugin) runNRI(ctx context.Context) error {
	backoff := nriBackoffMin
	failingSince := time.Time{}
	for {
		started := time.Now()
		err := p.stub.Run(ctx)
		p.setReady(false)
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
		p.metrics.nriReconnects.Inc()
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
	p.setReady(true)
	return nil, nil
}

func (p *Plugin) CreateContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	log := p.log.With("namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName(), "id", ctr.GetId())
	if keys := unknownCainjektKeys(pod); len(keys) > 0 {
		log.Warn("pod has unrecognized cainjekt annotations (typo?)", "keys", keys, "known", []string{
			config.AnnoEnabled, config.AnnoProcessorsInclude, config.AnnoProcessorsExclude,
		})
	}
	if !shouldInject(pod) {
		p.metrics.skipped.WithLabelValues(skipNotEnabled).Inc()
		log.Debug("skip: not enabled", "annotation", config.AnnoEnabled)
		return nil, nil, nil
	}

	// Use env var if set (for DaemonSet deployment), otherwise use os.Executable()
	self := getenvOr(config.EnvPluginBinaryPath, "")
	if self == "" {
		var err error
		self, err = os.Executable()
		if err != nil {
			p.metrics.injectionErrors.Inc()
			return nil, nil, fmt.Errorf("failed to determine plugin binary path: %w", err)
		}
	}

	sourceCAFile := getenvOr(config.EnvCAFile, config.DefaultCAFile)
	caFileForHook, err := p.stageCA(sourceCAFile, ctr)
	if err != nil {
		p.metrics.injectionErrors.Inc()
		_ = cleanupDynamicCAFile(dynamicCARoot(), ctr)
		// An error here fails the container creation, so only return it
		// under fail-closed; otherwise start the container uninjected.
		if config.IsFailClosed(p.failPolicy) {
			return nil, nil, err
		}
		p.metrics.skipped.WithLabelValues(skipInjectionError).Inc()
		log.Error("failed to stage CA bundle, starting container without injection (fail-open)", "error", err)
		return nil, nil, nil
	}
	if key, err := containerCAKey(ctr); err == nil {
		p.tracked.add(key)
	}

	hook := &api.Hook{
		Path: self,
		Env: []string{
			config.EnvHookMode + "=" + config.ModeCreateRT,
			config.EnvCAFile + "=" + caFileForHook,
			config.EnvFailPolicy + "=" + p.failPolicy,
			config.EnvHookTimeoutSec + "=" + strconv.Itoa(p.hookTimeoutSec),
			config.EnvHookContextFile + "=" + config.HookContextFile,
		},
		Timeout: api.Int(p.hookTimeoutSec),
	}

	adjustment := &api.ContainerAdjustment{}
	adjustment.AddEnv(config.EnvWrapperMode, "1")
	// The wrapper falls back to this when the hook context is unreadable.
	adjustment.AddEnv(config.EnvFailPolicy, p.failPolicy)
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
	p.metrics.injected.Inc()
	log.Info("inject", "ca_file", caFileForHook,
		"processors.include", pod.GetAnnotations()[config.AnnoProcessorsInclude],
		"processors.exclude", pod.GetAnnotations()[config.AnnoProcessorsExclude])
	return adjustment, nil, nil
}

// stageCA reads the source CA bundle, updates the CA bundle metrics from it
// and stages it for the container.
func (p *Plugin) stageCA(sourceCAFile string, ctr *api.Container) (string, error) {
	content, err := readSourceCAFile(sourceCAFile)
	if err != nil {
		return "", err
	}
	p.metrics.observeCABundle(content)
	return stageDynamicCAFile(content, dynamicCARoot(), ctr)
}

func (p *Plugin) RemoveContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	if key, err := containerCAKey(ctr); err == nil {
		p.tracked.remove(key)
	}
	if !shouldInject(pod) {
		return nil
	}
	if err := cleanupDynamicCAFile(dynamicCARoot(), ctr); err != nil {
		p.log.Warn("failed to cleanup dynamic CA bundle", "namespace", pod.GetNamespace(), "pod", pod.GetName(),
			"container", ctr.GetName(), "error", err)
	}
	return nil
}
