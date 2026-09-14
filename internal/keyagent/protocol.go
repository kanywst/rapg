// Package keyagent caches an unlocked vault key in a local agent process so
// that short-lived rapg invocations (a shell hook firing on every `cd`, say)
// do not each have to pay an Argon2id derivation and a password prompt.
//
// The key never leaves the agent. Clients ask for resolved environment
// variables and the agent answers from the key it holds in protected memory;
// see docs/key-cache-design.md for why the protocol is shaped that way.
package keyagent

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Op names a request kind. Unknown ops are rejected rather than ignored.
type Op string

const (
	// OpEnv asks the agent to resolve env-tagged secrets for a project scope.
	OpEnv Op = "env"
	// OpStatus asks whether the agent holds a key, and for how much longer.
	OpStatus Op = "status"
	// OpLock discards the held key. The agent keeps listening.
	OpLock Op = "lock"
)

// maxRequestBytes bounds a single request line. The largest legitimate
// request is a keys whitelist, which is a handful of env var names; anything
// past this is a client bug or an attempt to make the agent allocate.
const maxRequestBytes = 64 << 10

// Request is one client call. Namespace, InheritGlobal and Keys mirror the
// fields config.Project exposes, because the client resolves .rapg.toml and
// the agent applies the same scoping rules to them.
//
// These fields scope the answer; they are not a security boundary. A process
// running as the user can write its own .rapg.toml, and could already read
// whatever `rapg run` would have injected. The boundary the agent does
// enforce is the peer uid.
type Request struct {
	Op Op `json:"op"`

	Namespace     string `json:"namespace,omitempty"`
	InheritGlobal bool   `json:"inherit_global,omitempty"`
	// Keys is the .rapg.toml whitelist. Its three states are load-bearing and
	// match config.Project.Keys exactly: nil means no whitelist, empty means
	// deny everything, non-empty means allow just those.
	Keys []string `json:"keys,omitempty"`
	// HasKeys distinguishes a nil Keys from an empty one across the wire,
	// because JSON cannot: both marshal to an absent field under omitempty.
	HasKeys bool `json:"has_keys,omitempty"`
}

// Response is one agent reply. Err is set when Ok is false.
type Response struct {
	Ok  bool   `json:"ok"`
	Err string `json:"err,omitempty"`

	// Env carries the resolved variables for OpEnv.
	Env map[string]string `json:"env,omitempty"`

	// Unlocked and ExpiresInSeconds answer OpStatus.
	Unlocked         bool  `json:"unlocked,omitempty"`
	ExpiresInSeconds int64 `json:"expires_in_seconds,omitempty"`
}

// ErrNoAgent reports that no agent is listening. Callers treat this as
// "fall back to prompting", not as a failure.
var ErrNoAgent = errors.New("keyagent: no agent listening")

// ErrLocked reports that the agent is running but holds no key.
var ErrLocked = errors.New("keyagent: agent holds no key")

// writeMessage frames one JSON value as a single line. Newline-delimited JSON
// keeps the framing trivial to reason about; json.Encoder already refuses to
// emit a bare newline inside a value.
func writeMessage(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// readMessage reads one newline-delimited JSON value, refusing anything over
// maxRequestBytes so a peer cannot make the reader allocate without bound.
func readMessage(r *bufio.Reader, v any) error {
	line, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return fmt.Errorf("keyagent: request exceeds %d bytes", maxRequestBytes)
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(line, v)
}

// SocketPath returns the path the agent listens on.
//
// XDG_RUNTIME_DIR is preferred where the OS provides one (systemd sets it to
// a per-user tmpfs that is cleared on logout, which is exactly the lifetime a
// key cache wants). macOS has no such directory, so the vault directory is
// used instead; it is already created at 0700 by storage.InitDB.
func SocketPath() (string, error) {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "rapg", "agent.sock"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".rapg", "agent.sock"), nil
}
