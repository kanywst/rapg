package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kanywst/rapg/internal/config"
	"github.com/kanywst/rapg/internal/core"
	"github.com/kanywst/rapg/internal/keyagent"
	"github.com/spf13/cobra"
)

// newAgentCmd builds `rapg agent`, the key cache that lets short-lived
// invocations skip the Argon2id derivation and the password prompt.
//
// The agent runs in the foreground on purpose. Backgrounding it is one `&`
// away, and a process holding your master key should not appear without you
// asking for it; see docs/key-cache-design.md.
func newAgentCmd() *cobra.Command {
	var idle, ttl time.Duration

	agentCmd := &cobra.Command{
		Use:   "agent",
		Short: "Cache an unlocked vault key for short-lived invocations",
		Long: `Hold the unlocked vault key in memory so that 'rapg run' and 'rapg export'
do not prompt for the master password every time.

The agent never hands the key out. Clients ask it to resolve env-tagged
secrets for a project scope and it answers from the key it holds, the way
ssh-agent signs rather than giving up the private key.

It listens on a unix socket that only your uid can reach, and forgets the key
after an idle timeout or an absolute deadline, whichever comes first.`,
	}

	startCmd := &cobra.Command{
		Use:    "start",
		Short:  "Unlock the vault and hold the key until it expires",
		PreRun: openVault,
		Run: func(cmd *cobra.Command, args []string) {
			runAgent(idle, ttl)
		},
	}
	startCmd.Flags().DurationVar(&idle, "idle", keyagent.DefaultIdleTimeout,
		"forget the key after this long without use")
	startCmd.Flags().DurationVar(&ttl, "ttl", keyagent.DefaultTTL,
		"forget the key this long after starting, used or not")

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Report whether an agent is running and holding a key",
		Run: func(cmd *cobra.Command, args []string) {
			runAgentStatus()
		},
	}

	lockCmd := &cobra.Command{
		Use:   "lock",
		Short: "Make the agent forget its key without shutting down",
		Run: func(cmd *cobra.Command, args []string) {
			runAgentSimple(keyagent.Lock, "locked")
		},
	}

	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Make the agent forget its key and exit",
		Run: func(cmd *cobra.Command, args []string) {
			runAgentSimple(keyagent.Stop, "stopped")
		},
	}

	agentCmd.AddCommand(startCmd, statusCmd, lockCmd, stopCmd)
	return agentCmd
}

// runAgent unlocks the vault, hands the key to a server and blocks.
func runAgent(idle, ttl time.Duration) {
	path, err := keyagent.SocketPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving the agent socket path: %v\n", err)
		os.Exit(1)
	}

	unlockVault()

	srv, err := keyagent.NewServer(keyagent.Config{
		SocketPath:  path,
		Key:         core.TakeSessionKey(),
		Resolve:     agentResolver,
		IdleTimeout: idle,
		TTL:         ttl,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting the agent: %v\n", err)
		os.Exit(1)
	}

	// A terminated agent must not leave its socket behind for the next start
	// to have to reclaim, and the key should go with it.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		_ = srv.Close()
	}()

	fmt.Fprintf(os.Stderr, "[rapg] agent listening on %s (idle %s, ttl %s)\n", path, idle, ttl)
	if err := srv.Serve(); err != nil && !errors.Is(err, net.ErrClosed) {
		fmt.Fprintf(os.Stderr, "Agent error: %v\n", err)
		os.Exit(1)
	}
}

func runAgentStatus() {
	path, err := keyagent.SocketPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving the agent socket path: %v\n", err)
		os.Exit(1)
	}

	resp, err := keyagent.Status(path)
	if errors.Is(err, keyagent.ErrNoAgent) {
		fmt.Println("not running")
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error talking to the agent: %v\n", err)
		os.Exit(1)
	}

	if !resp.Unlocked {
		fmt.Println("running, locked")
		return
	}
	fmt.Printf("running, unlocked (expires in %s)\n",
		(time.Duration(resp.ExpiresInSeconds) * time.Second).Round(time.Second))
}

// runAgentSimple runs an op that has nothing to report beyond success.
func runAgentSimple(op func(string) error, done string) {
	path, err := keyagent.SocketPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving the agent socket path: %v\n", err)
		os.Exit(1)
	}

	err = op(path)
	if errors.Is(err, keyagent.ErrNoAgent) {
		fmt.Fprintln(os.Stderr, "No agent is running.")
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error talking to the agent: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(done)
}

// agentResolver answers an agent request using the key the agent holds. It
// runs inside the agent process, which has already opened the vault.
func agentResolver(key []byte, req keyagent.Request) (map[string]string, error) {
	return core.GetEnvVarsWithKey(key, projectFromRequest(req))
}

// projectFromRequest rebuilds the caller's project scope.
//
// The nil-versus-empty distinction on Keys is load-bearing (see
// config.Project.Allows), and JSON collapses both to an absent field, so
// HasKeys carries it and an empty slice has to be rebuilt explicitly.
func projectFromRequest(req keyagent.Request) *config.Project {
	if !req.HasProject {
		return nil
	}
	p := &config.Project{
		Namespace:     req.Namespace,
		InheritGlobal: req.InheritGlobal,
	}
	if req.HasKeys {
		p.Keys = req.Keys
		if p.Keys == nil {
			p.Keys = []string{}
		}
	}
	return p
}

// requestFromProject is the inverse, run on the client side.
func requestFromProject(p *config.Project) keyagent.Request {
	if p == nil {
		return keyagent.Request{}
	}
	return keyagent.Request{
		HasProject:    true,
		Namespace:     p.Namespace,
		InheritGlobal: p.InheritGlobal,
		Keys:          p.Keys,
		HasKeys:       p.Keys != nil,
	}
}

// resolveEnvVars returns the env-tagged secrets for a project scope, asking a
// running agent first and falling back to a password prompt.
//
// The fallback is the normal path: with no agent running this is exactly what
// `rapg run` did before the agent existed. Only a genuine failure to talk to a
// live agent is worth a warning; "not running" and "locked" are ordinary.
func resolveEnvVars(project *config.Project) (map[string]string, error) {
	if env, ok := envFromAgent(project); ok {
		return env, nil
	}
	unlockVault()
	return core.GetEnvVars(project)
}

// envFromAgent asks a running agent for a project's env vars. ok is false when
// the caller should prompt instead.
//
// Split out from resolveEnvVars so it can be tested end to end: the fallback
// reads a password from the terminal, which a test cannot sit through.
func envFromAgent(project *config.Project) (env map[string]string, ok bool) {
	path, err := keyagent.SocketPath()
	if err != nil {
		return nil, false
	}

	env, err = keyagent.Env(path, requestFromProject(project))
	switch {
	case err == nil:
		return env, true
	case errors.Is(err, keyagent.ErrNoAgent), errors.Is(err, keyagent.ErrLocked):
		// Ordinary, not worth a word: no agent running, or it has forgotten
		// its key. Prompting is the normal path.
		return nil, false
	default:
		fmt.Fprintf(os.Stderr, "[rapg] warning: agent unusable, prompting instead: %v\n", err)
		return nil, false
	}
}
