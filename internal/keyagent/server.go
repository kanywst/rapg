package keyagent

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/awnumar/memguard"
)

// Default lifetimes. See docs/key-cache-design.md: ssh-agent defaults to
// unlimited, which is the wrong default for a tool whose pitch is blast-radius
// reduction, so the agent expires on both axes by default.
const (
	DefaultIdleTimeout = 15 * time.Minute
	DefaultTTL         = 8 * time.Hour
)

// EnvResolver turns a scoped request into resolved environment variables,
// using the vault key the agent is holding.
//
// It is injected rather than imported so this package stays a leaf: it never
// reaches into storage or crypto itself, and tests can exercise the socket
// lifecycle without a vault on disk. The wiring commit supplies an
// implementation backed by core.
//
// The key slice is only valid for the duration of the call; implementations
// must not retain it.
type EnvResolver func(key []byte, req Request) (map[string]string, error)

// Config describes an agent. Key ownership transfers to the Server, which
// destroys the buffer on Close or on expiry.
type Config struct {
	SocketPath  string
	Key         *memguard.LockedBuffer
	Resolve     EnvResolver
	IdleTimeout time.Duration
	TTL         time.Duration

	// now is swappable in tests. nil means time.Now.
	now func() time.Time
}

// Server holds an unlocked vault key and answers scoped requests over a unix
// socket. The key never crosses the socket; see docs/key-cache-design.md.
type Server struct {
	mu       sync.Mutex
	key      *memguard.LockedBuffer
	lastUse  time.Time
	deadline time.Time

	resolve     EnvResolver
	idleTimeout time.Duration
	now         func() time.Time

	ln         *net.UnixListener
	socketPath string

	closeOnce sync.Once
	done      chan struct{}
}

// NewServer binds the socket and takes ownership of cfg.Key.
//
// On failure the key is destroyed before returning, so a caller that hands
// over a key never has to reason about whether it still owns it.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Key == nil {
		return nil, errors.New("keyagent: no key")
	}
	if cfg.Resolve == nil {
		cfg.Key.Destroy()
		return nil, errors.New("keyagent: no resolver")
	}
	if cfg.SocketPath == "" {
		cfg.Key.Destroy()
		return nil, errors.New("keyagent: no socket path")
	}

	now := cfg.now
	if now == nil {
		now = time.Now
	}
	idle := cfg.IdleTimeout
	if idle <= 0 {
		idle = DefaultIdleTimeout
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}

	ln, err := listen(cfg.SocketPath)
	if err != nil {
		cfg.Key.Destroy()
		return nil, err
	}

	start := now()
	return &Server{
		key:         cfg.Key,
		lastUse:     start,
		deadline:    start.Add(ttl),
		resolve:     cfg.Resolve,
		idleTimeout: idle,
		now:         now,
		ln:          ln,
		socketPath:  cfg.SocketPath,
		done:        make(chan struct{}),
	}, nil
}

// maxSocketPath is the smallest sun_path any target platform gives us (104 on
// darwin, 108 on Linux), minus the NUL. Going over produces a bare "invalid
// argument" from bind, which is a miserable thing to debug, so it is caught
// here with a message that says what actually happened.
const maxSocketPath = 103

// listen creates the socket directory at 0700, clears a stale socket left by
// a crashed agent, and binds.
func listen(path string) (*net.UnixListener, error) {
	if len(path) > maxSocketPath {
		return nil, fmt.Errorf("keyagent: socket path is %d bytes, limit is %d: %s", len(path), maxSocketPath, path)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	// A directory that already existed may be looser than we want. The peer-uid
	// check is the real guard, but there is no reason to leave the door open.
	//
	// #nosec G302 -- gosec's 0600 ceiling is a file rule. This is a directory,
	// and a directory without the owner execute bit cannot be traversed, so the
	// socket inside it would be unreachable. 0700 is the tightest mode that
	// works, and it matches the vault directory in storage.InitDB.
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}

	if err := clearStaleSocket(path); err != nil {
		return nil, err
	}

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	// Belt and braces with the directory mode: a socket nobody else can open.
	if err := os.Chmod(path, 0600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// clearStaleSocket removes a socket file that no live agent is listening on.
// A running agent is left alone, so a second start fails loudly with EADDRINUSE
// instead of silently stealing the first one's socket.
func clearStaleSocket(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	conn, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("keyagent: an agent is already listening on %s", path)
	}
	return os.Remove(path)
}

// Serve accepts connections until Close. It always returns a non-nil error,
// like http.Server.Serve; ErrClosed after a clean Close.
func (s *Server) Serve() error {
	defer s.Close()

	go s.expiryLoop()

	for {
		conn, err := s.ln.AcceptUnix()
		if err != nil {
			select {
			case <-s.done:
				return net.ErrClosed
			default:
			}
			return err
		}
		go s.handle(conn)
	}
}

// expiryLoop destroys the key once it is past either deadline. The agent keeps
// listening afterwards so clients get a clear "locked" answer rather than a
// connection error that looks like "no agent".
func (s *Server) expiryLoop() {
	// A tick well under the idle timeout keeps the window where an expired key
	// is still resident short without spinning.
	tick := s.idleTimeout / 10
	if tick < time.Second {
		tick = time.Second
	}
	t := time.NewTicker(tick)
	defer t.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			s.mu.Lock()
			s.expireLocked()
			s.mu.Unlock()
		}
	}
}

// expireLocked destroys the key if either deadline has passed. Callers hold mu.
func (s *Server) expireLocked() {
	if s.key == nil {
		return
	}
	now := s.now()
	if now.After(s.deadline) || now.Sub(s.lastUse) > s.idleTimeout {
		s.key.Destroy()
		s.key = nil
	}
}

// handle serves one connection: one request, one response, then close.
func (s *Server) handle(conn *net.UnixConn) {
	defer func() { _ = conn.Close() }()

	uid, err := peerUID(conn)
	if err != nil {
		// Refusing to answer a peer we cannot identify is the whole point of
		// the check, so a failure here is a refusal, not a warning.
		_ = writeMessage(conn, Response{Err: "peer identity unavailable"})
		return
	}
	// Widened to int64 on both sides so the comparison cannot wrap on a 32-bit
	// int, and so it stays a comparison rather than a narrowing conversion.
	if int64(uid) != int64(os.Getuid()) {
		_ = writeMessage(conn, Response{Err: "permission denied"})
		return
	}

	// A client that connects and then says nothing must not pin a goroutine.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var req Request
	r := bufio.NewReaderSize(conn, maxRequestBytes)
	if err := readMessage(r, &req); err != nil {
		_ = writeMessage(conn, Response{Err: "malformed request"})
		return
	}

	_ = writeMessage(conn, s.dispatch(req))
}

// dispatch runs one request against the held key.
func (s *Server) dispatch(req Request) Response {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Expire before answering, so a request arriving after the deadline never
	// gets served by a key that a tick has not collected yet.
	s.expireLocked()

	switch req.Op {
	case OpStatus:
		if s.key == nil {
			return Response{Ok: true, Unlocked: false}
		}
		return Response{
			Ok:               true,
			Unlocked:         true,
			ExpiresInSeconds: int64(s.expiresInLocked() / time.Second),
		}

	case OpLock:
		if s.key != nil {
			s.key.Destroy()
			s.key = nil
		}
		return Response{Ok: true}

	case OpEnv:
		if s.key == nil {
			return Response{Err: ErrLocked.Error()}
		}
		env, err := s.resolve(s.key.Bytes(), req)
		if err != nil {
			return Response{Err: err.Error()}
		}
		// Only a request the key actually served counts as use. A status poll
		// from a shell prompt must not hold the key open indefinitely.
		s.lastUse = s.now()
		return Response{Ok: true, Env: env}

	default:
		return Response{Err: fmt.Sprintf("unknown op %q", req.Op)}
	}
}

// expiresInLocked reports how long the key has left, whichever deadline bites
// first. Callers hold mu and have checked that key is non-nil.
func (s *Server) expiresInLocked() time.Duration {
	now := s.now()
	untilIdle := s.idleTimeout - now.Sub(s.lastUse)
	untilDeadline := s.deadline.Sub(now)
	if untilIdle < untilDeadline {
		return untilIdle
	}
	return untilDeadline
}

// Close stops listening, removes the socket and destroys the key. It is safe
// to call more than once.
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.done)
		err = s.ln.Close()
		// Go's unix listener unlinks on Close, but only when it created the
		// file; removing again is harmless and covers the other case.
		_ = os.Remove(s.socketPath)

		s.mu.Lock()
		if s.key != nil {
			s.key.Destroy()
			s.key = nil
		}
		s.mu.Unlock()
	})
	return err
}
