// Package audit appends one JSON line per `rapg run` invocation to
// ~/.rapg/sessions.jsonl, recording which env keys were injected into
// which child process. The file is plaintext metadata — no secret values
// are ever written. Use `rapg session log` to read it back.
//
// File format: one JSON object per line, sorted by append order. The schema
// is intentionally additive — readers should ignore unknown fields.
package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// LogPath returns the absolute path to the session log under the user's
// home directory. The parent directory is the same one used by storage.
func LogPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".rapg", "sessions.jsonl"), nil
}

// Session is one row in the audit log.
type Session struct {
	Timestamp time.Time `json:"ts"`
	Command   string    `json:"cmd"`
	Args      []string  `json:"args,omitempty"`
	Namespace string    `json:"namespace,omitempty"`
	EnvKeys   []string  `json:"env_keys,omitempty"`
	ExitCode  int       `json:"exit"`
	PID       int       `json:"pid,omitempty"`
	Cwd       string    `json:"cwd,omitempty"`
}

// Write appends one Session as JSON to the log. EnvKeys is sorted in place
// so a downstream `rapg session log` shows stable output. The file is
// created with mode 0600 if missing.
func Write(s Session) error {
	if s.Timestamp.IsZero() {
		s.Timestamp = time.Now().UTC()
	}
	sort.Strings(s.EnvKeys)

	path, err := LogPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	// O_APPEND on POSIX is atomic for writes <= PIPE_BUF; one JSON line is
	// well under that, so concurrent `rapg run` invocations don't interleave.
	// #nosec G304 -- path is fixed at ~/.rapg/sessions.jsonl, derived from
	// os.UserHomeDir(); not influenced by external input.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	line, err := json.Marshal(s)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("append session log: %w", err)
	}
	return nil
}

// Read returns the last `limit` sessions, oldest first. limit <= 0 returns
// everything in the file. Streams via bufio.Scanner with a sliding window
// so memory stays bounded by `limit` even on large logs.
func Read(limit int) ([]Session, error) {
	path, err := LogPath()
	if err != nil {
		return nil, err
	}
	// #nosec G304 -- same fixed-path rationale as Write().
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var all []Session
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var s Session
		if err := json.Unmarshal(line, &s); err != nil {
			// Skip malformed lines silently — the log is a best-effort
			// audit trail, not authoritative state.
			continue
		}
		all = append(all, s)
		if limit > 0 && len(all) > limit {
			all = all[1:]
		}
	}
	return all, scanner.Err()
}
