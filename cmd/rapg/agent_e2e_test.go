//go:build linux || darwin

package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kanywst/rapg/internal/config"
	"github.com/kanywst/rapg/internal/core"
	"github.com/kanywst/rapg/internal/keyagent"
	"github.com/kanywst/rapg/internal/storage"
)

// startTestAgent builds a real vault, unlocks it, and hands the key to a real
// agent on a real socket. It exercises the whole path the CLI uses: vault ->
// TakeSessionKey -> keyagent -> agentResolver -> core.GetEnvVarsWithKey.
func startTestAgent(t *testing.T, entries []struct {
	namespace, service, envKey, password string
}) {
	t.Helper()

	t.Setenv("HOME", t.TempDir())
	if err := storage.InitDB(); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() {
		if storage.DB != nil {
			if sqlDB, err := storage.DB.DB(); err == nil {
				_ = sqlDB.Close()
			}
			storage.DB = nil
		}
		core.LockVault()
	})

	if err := core.InitializeVault([]byte("correct horse battery staple")); err != nil {
		t.Fatalf("InitializeVault: %v", err)
	}
	for _, e := range entries {
		err := core.AddEntry(e.namespace, e.service, "dev", storage.SecretData{
			Password: e.password,
			EnvKey:   e.envKey,
		})
		if err != nil {
			t.Fatalf("AddEntry %s: %v", e.service, err)
		}
	}

	// A short socket directory: sun_path is 104 bytes on darwin and t.TempDir
	// embeds the test name.
	dir, err := os.MkdirTemp("", "rapg")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("XDG_RUNTIME_DIR", dir)

	path, err := keyagent.SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}

	srv, err := keyagent.NewServer(keyagent.Config{
		SocketPath: path,
		Key:        core.TakeSessionKey(),
		Resolve:    agentResolver,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = srv.Serve()
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		wg.Wait()
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("agent socket %s never appeared", path)
}

func vaultFixture() []struct {
	namespace, service, envKey, password string
} {
	return []struct {
		namespace, service, envKey, password string
	}{
		{"", "github", "GITHUB_TOKEN", "ghp-global"},
		{"myapp", "postgres", "DATABASE_URL", "postgres://myapp"},
		{"myapp", "anthropic", "ANTHROPIC_API_KEY", "sk-ant-myapp"},
		{"other", "postgres", "DATABASE_URL", "postgres://other"},
	}
}

// The point of the whole exercise: a resolved secret comes back without the
// process ever holding the vault key. core.SessionKey is nil here, because
// TakeSessionKey moved it into the agent.
func TestAgentServesSecretsWithoutTheCallerHoldingTheKey(t *testing.T) {
	startTestAgent(t, vaultFixture())

	if core.SessionKey != nil {
		t.Fatal("the caller still holds a session key; the agent should own it")
	}

	env, ok := envFromAgent(&config.Project{Namespace: "myapp"})
	if !ok {
		t.Fatal("the agent did not answer")
	}
	if got := env["DATABASE_URL"]; got != "postgres://myapp" {
		t.Errorf("DATABASE_URL = %q, want postgres://myapp", got)
	}
	if got := env["ANTHROPIC_API_KEY"]; got != "sk-ant-myapp" {
		t.Errorf("ANTHROPIC_API_KEY = %q, want sk-ant-myapp", got)
	}
}

// Scoping has to survive the socket. These are the same rules core.GetEnvVars
// applies locally, checked through the agent instead.
func TestAgentAppliesTheScopingRules(t *testing.T) {
	startTestAgent(t, vaultFixture())

	t.Run("another project's namespace is invisible", func(t *testing.T) {
		env, ok := envFromAgent(&config.Project{Namespace: "myapp"})
		if !ok {
			t.Fatal("the agent did not answer")
		}
		if env["DATABASE_URL"] == "postgres://other" {
			t.Error("leaked the other project's DATABASE_URL")
		}
	})

	t.Run("globals are excluded by default", func(t *testing.T) {
		env, ok := envFromAgent(&config.Project{Namespace: "myapp"})
		if !ok {
			t.Fatal("the agent did not answer")
		}
		if _, present := env["GITHUB_TOKEN"]; present {
			t.Error("a global leaked into a project without inherit_global")
		}
	})

	t.Run("inherit_global opts in", func(t *testing.T) {
		env, ok := envFromAgent(&config.Project{Namespace: "myapp", InheritGlobal: true})
		if !ok {
			t.Fatal("the agent did not answer")
		}
		if got := env["GITHUB_TOKEN"]; got != "ghp-global" {
			t.Errorf("GITHUB_TOKEN = %q, want ghp-global", got)
		}
	})

	t.Run("no project means globals only", func(t *testing.T) {
		env, ok := envFromAgent(nil)
		if !ok {
			t.Fatal("the agent did not answer")
		}
		if got := env["GITHUB_TOKEN"]; got != "ghp-global" {
			t.Errorf("GITHUB_TOKEN = %q, want ghp-global", got)
		}
		if _, present := env["DATABASE_URL"]; present {
			t.Error("a namespaced secret leaked with no project context")
		}
	})

	t.Run("whitelist filters", func(t *testing.T) {
		env, ok := envFromAgent(&config.Project{Namespace: "myapp", Keys: []string{"DATABASE_URL"}})
		if !ok {
			t.Fatal("the agent did not answer")
		}
		if _, present := env["ANTHROPIC_API_KEY"]; present {
			t.Error("a key outside the whitelist was injected")
		}
		if got := env["DATABASE_URL"]; got != "postgres://myapp" {
			t.Errorf("DATABASE_URL = %q, want postgres://myapp", got)
		}
	})

	t.Run("explicit deny-all injects nothing", func(t *testing.T) {
		env, ok := envFromAgent(&config.Project{Namespace: "myapp", Keys: []string{}})
		if !ok {
			t.Fatal("the agent did not answer")
		}
		if len(env) != 0 {
			t.Errorf("deny-all returned %v, want nothing", env)
		}
	})
}

// A locked agent must tell the caller to prompt rather than answering with an
// empty set, which would silently run the child with no secrets.
func TestLockedAgentFallsBackRatherThanReturningNothing(t *testing.T) {
	startTestAgent(t, vaultFixture())

	path, err := keyagent.SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	if err := keyagent.Lock(path); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	if env, ok := envFromAgent(&config.Project{Namespace: "myapp"}); ok {
		t.Fatalf("a locked agent answered with %v; the caller should fall back to prompting", env)
	}
}

// With no agent at all the caller must fall back, which is the default state
// for anyone who has not run `rapg agent start`.
func TestNoAgentFallsBack(t *testing.T) {
	dir, err := os.MkdirTemp("", "rapg")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "empty"))

	if _, ok := envFromAgent(&config.Project{Namespace: "myapp"}); ok {
		t.Fatal("envFromAgent reported success with no agent running")
	}
}
