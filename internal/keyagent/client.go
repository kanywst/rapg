package keyagent

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// dialTimeout bounds the connect. The agent is a local process on a unix
// socket, so anything slow here means something is wrong, not busy.
const dialTimeout = 2 * time.Second

// Do sends one request to the agent at path and returns its response.
//
// It reports ErrNoAgent when nothing is listening, which callers should treat
// as "fall back to prompting for the master password" rather than as an error
// worth showing the user.
func Do(path string, req Request) (*Response, error) {
	conn, err := net.DialTimeout("unix", path, dialTimeout)
	if err != nil {
		if isNoAgent(err) {
			return nil, ErrNoAgent
		}
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, err
	}
	if err := writeMessage(conn, req); err != nil {
		return nil, err
	}

	var resp Response
	if err := readMessage(bufio.NewReaderSize(conn, maxRequestBytes), &resp); err != nil {
		return nil, err
	}
	if !resp.Ok && resp.Err != "" {
		if resp.Err == ErrLocked.Error() {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("keyagent: %s", resp.Err)
	}
	return &resp, nil
}

// isNoAgent reports whether err means "nothing is listening there", as opposed
// to a socket that exists but misbehaved. A missing file and a refused connect
// both mean the agent is not running.
func isNoAgent(err error) bool {
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Op == "dial"
	}
	return false
}

// Env asks the agent to resolve env-tagged secrets for a project scope.
func Env(path string, req Request) (map[string]string, error) {
	req.Op = OpEnv
	resp, err := Do(path, req)
	if err != nil {
		return nil, err
	}
	return resp.Env, nil
}

// Status reports whether an agent is listening and holding a key.
func Status(path string) (*Response, error) {
	return Do(path, Request{Op: OpStatus})
}

// Lock asks the agent to discard its key without shutting down.
func Lock(path string) error {
	_, err := Do(path, Request{Op: OpLock})
	return err
}

// Stop asks the agent to discard its key and exit.
func Stop(path string) error {
	_, err := Do(path, Request{Op: OpStop})
	return err
}
