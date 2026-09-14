//go:build linux || darwin

package keyagent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awnumar/memguard"
)

// testKey is the 32 bytes a real agent would be holding after Argon2id.
func testKey(t *testing.T) *memguard.LockedBuffer {
	t.Helper()
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return memguard.NewBufferFromBytes(b)
}

// echoResolver reports the key it was handed plus the scope it was asked for,
// which is enough to assert that the right key reached the resolver and that
// the scoping fields survived the round trip.
func echoResolver(key []byte, req Request) (map[string]string, error) {
	return map[string]string{
		"KEY_LEN":   string(rune('0' + len(key)/32)),
		"NAMESPACE": req.Namespace,
		"KEYS":      strings.Join(req.Keys, ","),
		"HAS_KEYS":  map[bool]string{true: "yes", false: "no"}[req.HasKeys],
		"INHERIT":   map[bool]string{true: "yes", false: "no"}[req.InheritGlobal],
	}, nil
}

// shortTempDir returns a temp directory whose path is short enough to hold a
// socket. t.TempDir embeds the test name, which on macOS is enough to push
// sun_path past its 104-byte limit and fail with a bare "invalid argument".
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rapg")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// startAgent brings up a server on a socket under a temp dir and tears it down
// when the test ends.
func startAgent(t *testing.T, cfg Config) (*Server, string) {
	t.Helper()

	if cfg.SocketPath == "" {
		cfg.SocketPath = filepath.Join(shortTempDir(t), "agent.sock")
	}
	if cfg.Key == nil {
		cfg.Key = testKey(t)
	}
	if cfg.Resolve == nil {
		cfg.Resolve = echoResolver
	}

	srv, err := NewServer(cfg)
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

	waitForSocket(t, cfg.SocketPath)
	return srv, cfg.SocketPath
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("socket %s never appeared", path)
}

func TestEnvRoundTrip(t *testing.T) {
	_, path := startAgent(t, Config{})

	env, err := Env(path, Request{
		Namespace:     "myapp",
		InheritGlobal: true,
		Keys:          []string{"DATABASE_URL", "ANTHROPIC_API_KEY"},
		HasKeys:       true,
	})
	if err != nil {
		t.Fatalf("Env: %v", err)
	}

	if got := env["NAMESPACE"]; got != "myapp" {
		t.Errorf("namespace = %q, want %q", got, "myapp")
	}
	if got := env["KEYS"]; got != "DATABASE_URL,ANTHROPIC_API_KEY" {
		t.Errorf("keys = %q", got)
	}
	if got := env["INHERIT"]; got != "yes" {
		t.Errorf("inherit_global = %q, want yes", got)
	}
	if got := env["HAS_KEYS"]; got != "yes" {
		t.Errorf("has_keys = %q, want yes", got)
	}
	if got := env["KEY_LEN"]; got != "1" {
		t.Errorf("resolver saw a %s*32-byte key, want 1*32", got)
	}
}

// The nil-vs-empty distinction on Keys is load-bearing in .rapg.toml (omitted
// means no whitelist, [] means deny everything), and JSON cannot carry it on
// its own because both marshal to an absent field. HasKeys is what preserves
// it, so it gets its own test.
func TestKeysNilVersusEmptySurvivesTheWire(t *testing.T) {
	_, path := startAgent(t, Config{})

	noWhitelist, err := Env(path, Request{Namespace: "a", Keys: nil, HasKeys: false})
	if err != nil {
		t.Fatalf("Env: %v", err)
	}
	if got := noWhitelist["HAS_KEYS"]; got != "no" {
		t.Errorf("nil Keys arrived as has_keys=%q, want no", got)
	}

	denyAll, err := Env(path, Request{Namespace: "a", Keys: []string{}, HasKeys: true})
	if err != nil {
		t.Fatalf("Env: %v", err)
	}
	if got := denyAll["HAS_KEYS"]; got != "yes" {
		t.Errorf("empty Keys arrived as has_keys=%q, want yes", got)
	}
	if got := denyAll["KEYS"]; got != "" {
		t.Errorf("empty Keys arrived as %q, want empty", got)
	}
}

func TestStatusReportsUnlockedThenLocked(t *testing.T) {
	_, path := startAgent(t, Config{TTL: time.Hour, IdleTimeout: time.Hour})

	resp, err := Status(path)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !resp.Unlocked {
		t.Fatal("fresh agent reports locked")
	}
	if resp.ExpiresInSeconds <= 0 {
		t.Errorf("expires_in_seconds = %d, want > 0", resp.ExpiresInSeconds)
	}

	if err := Lock(path); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	resp, err = Status(path)
	if err != nil {
		t.Fatalf("Status after lock: %v", err)
	}
	if resp.Unlocked {
		t.Error("agent still reports unlocked after Lock")
	}
}

func TestEnvAfterLockIsRefused(t *testing.T) {
	_, path := startAgent(t, Config{})

	if err := Lock(path); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	_, err := Env(path, Request{Namespace: "myapp"})
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("err = %v, want ErrLocked", err)
	}
}

// A key past its absolute deadline must not be served even if the expiry tick
// has not fired yet, so dispatch re-checks before answering.
func TestExpiredKeyIsNotServed(t *testing.T) {
	now := time.Now()
	var mu sync.Mutex
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}

	_, path := startAgent(t, Config{
		TTL:         time.Hour,
		IdleTimeout: 30 * time.Minute,
		now:         clock,
	})

	if _, err := Env(path, Request{Namespace: "myapp"}); err != nil {
		t.Fatalf("Env before expiry: %v", err)
	}

	advance(2 * time.Hour)

	if _, err := Env(path, Request{Namespace: "myapp"}); !errors.Is(err, ErrLocked) {
		t.Fatalf("err after TTL = %v, want ErrLocked", err)
	}
}

// Idle expiry is the other axis: a key that is never used must lapse even
// while the absolute deadline is far away.
func TestIdleTimeoutExpiresTheKey(t *testing.T) {
	now := time.Now()
	var mu sync.Mutex
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}

	_, path := startAgent(t, Config{
		TTL:         24 * time.Hour,
		IdleTimeout: 10 * time.Minute,
		now:         clock,
	})

	mu.Lock()
	now = now.Add(11 * time.Minute)
	mu.Unlock()

	if _, err := Env(path, Request{Namespace: "myapp"}); !errors.Is(err, ErrLocked) {
		t.Fatalf("err after idle timeout = %v, want ErrLocked", err)
	}
}

// A status poll is not use. A shell prompt calling Status every second must
// not keep the key alive forever.
func TestStatusDoesNotRefreshIdleTimer(t *testing.T) {
	now := time.Now()
	var mu sync.Mutex
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}

	_, path := startAgent(t, Config{
		TTL:         24 * time.Hour,
		IdleTimeout: 10 * time.Minute,
		now:         clock,
	})

	for i := 0; i < 3; i++ {
		advance(4 * time.Minute)
		if _, err := Status(path); err != nil {
			t.Fatalf("Status: %v", err)
		}
	}

	if _, err := Env(path, Request{Namespace: "myapp"}); !errors.Is(err, ErrLocked) {
		t.Fatalf("err = %v, want ErrLocked after 12 idle minutes of polling", err)
	}
}

func TestNoAgentIsDistinguishable(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "nothing.sock")

	_, err := Status(path)
	if !errors.Is(err, ErrNoAgent) {
		t.Fatalf("err = %v, want ErrNoAgent", err)
	}
}

// A crashed agent leaves its socket file behind. The next start must reclaim
// it rather than refusing to bind.
func TestStaleSocketIsReclaimed(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "agent.sock")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatalf("seed stale socket: %v", err)
	}

	_, got := startAgent(t, Config{SocketPath: path})
	if got != path {
		t.Fatalf("socket path = %q, want %q", got, path)
	}

	if _, err := Status(path); err != nil {
		t.Fatalf("Status on reclaimed socket: %v", err)
	}
}

// Two agents on one socket would be ambiguous about which key answers, so the
// second start is refused instead of stealing the socket.
func TestSecondAgentOnSameSocketIsRefused(t *testing.T) {
	_, path := startAgent(t, Config{})

	key := testKey(t)
	_, err := NewServer(Config{SocketPath: path, Key: key, Resolve: echoResolver})
	if err == nil {
		t.Fatal("second NewServer succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "already listening") {
		t.Errorf("err = %v, want an 'already listening' error", err)
	}
}

// NewServer takes ownership of the key, so every failure path must destroy it
// rather than leaving the caller unsure whether to.
func TestNewServerDestroysKeyOnFailure(t *testing.T) {
	key := testKey(t)

	if _, err := NewServer(Config{SocketPath: "", Key: key, Resolve: echoResolver}); err == nil {
		t.Fatal("NewServer with no socket path succeeded")
	}

	if key.IsAlive() {
		t.Error("key survived a failed NewServer")
	}
}

func TestCloseDestroysTheKey(t *testing.T) {
	key := testKey(t)
	srv, path := startAgent(t, Config{Key: key})

	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if key.IsAlive() {
		t.Error("key survived Close")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("socket still present after Close: %v", err)
	}

	// Close is documented as safe to repeat.
	if err := srv.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestUnknownOpIsRejected(t *testing.T) {
	_, path := startAgent(t, Config{})

	_, err := Do(path, Request{Op: Op("exfiltrate")})
	if err == nil {
		t.Fatal("unknown op accepted")
	}
	if !strings.Contains(err.Error(), "unknown op") {
		t.Errorf("err = %v, want an unknown-op error", err)
	}
}

func TestResolverErrorReachesTheClient(t *testing.T) {
	_, path := startAgent(t, Config{
		Resolve: func([]byte, Request) (map[string]string, error) {
			return nil, errors.New("vault locked")
		},
	})

	_, err := Env(path, Request{Namespace: "myapp"})
	if err == nil || !strings.Contains(err.Error(), "vault locked") {
		t.Fatalf("err = %v, want the resolver's error", err)
	}
}

// The socket must not be reachable by other users. The peer-uid check is the
// real guard, but the directory mode is what stops them getting that far.
func TestSocketDirectoryIsPrivate(t *testing.T) {
	_, path := startAgent(t, Config{})

	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat socket dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Errorf("socket dir mode = %04o, want 0700", perm)
	}
}

func TestSocketPathPrefersXDGRuntimeDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")

	got, err := SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	if want := filepath.Join("/run/user/1000", "rapg", "agent.sock"); got != want {
		t.Errorf("SocketPath() = %q, want %q", got, want)
	}
}

func TestSocketPathFallsBackToVaultDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")

	got, err := SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	if want := filepath.Join(home, ".rapg", "agent.sock"); got != want {
		t.Errorf("SocketPath() = %q, want %q", got, want)
	}
}

// An oversized request must be refused rather than allocated.
func TestOversizedRequestIsRefused(t *testing.T) {
	_, path := startAgent(t, Config{})

	huge := make([]string, 0, 4096)
	for i := 0; i < 4096; i++ {
		huge = append(huge, strings.Repeat("K", 64))
	}

	_, err := Env(path, Request{Namespace: "myapp", Keys: huge, HasKeys: true})
	if err == nil {
		t.Fatal("oversized request accepted")
	}
}

// sun_path is short, and blowing past it yields a bare "invalid argument" from
// bind. The limit is checked up front so the error names the real problem.
func TestOverlongSocketPathIsRejectedClearly(t *testing.T) {
	dir := shortTempDir(t)
	long := filepath.Join(dir, strings.Repeat("d", maxSocketPath), "agent.sock")

	key := testKey(t)
	_, err := NewServer(Config{SocketPath: long, Key: key, Resolve: echoResolver})
	if err == nil {
		t.Fatal("overlong socket path accepted")
	}
	if !strings.Contains(err.Error(), "limit is") {
		t.Errorf("err = %v, want a path-length error", err)
	}
	if key.IsAlive() {
		t.Error("key survived a failed NewServer")
	}
}
