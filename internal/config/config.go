// Package config loads .rapg.toml — the per-project file that scopes which
// secrets `rapg run` injects into a child process.
//
// File schema:
//
//	# .rapg.toml
//	namespace = "myapp"          # required: matches PasswordEntry.Namespace
//	keys = ["DATABASE_URL", ...] # optional: explicit env-key whitelist;
//	                             # if omitted, all entries in the namespace
//	                             # whose Env Key is non-empty are injected.
//
// Discovery: the loader walks up from a starting directory looking for
// `.rapg.toml`, stopping at the filesystem root. The first match wins.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/BurntSushi/toml"
)

// Filename is the file rapg looks for in the project hierarchy.
const Filename = ".rapg.toml"

// Project is the parsed contents of .rapg.toml.
type Project struct {
	Namespace string   `toml:"namespace"`
	Keys      []string `toml:"keys,omitempty"`
}

// Allows reports whether the given env key is permitted by this project's
// keys whitelist. An empty Keys list means "no whitelist" — all keys allowed.
func (p *Project) Allows(envKey string) bool {
	if len(p.Keys) == 0 {
		return true
	}
	return slices.Contains(p.Keys, envKey)
}

// ErrNotFound is returned when no .rapg.toml exists in the directory chain.
// Callers treat this as "no project context" — `rapg run` falls back to
// injecting all env-tagged secrets in the global (empty) namespace.
var ErrNotFound = errors.New("no .rapg.toml found in directory chain")

// Find walks up from startDir looking for .rapg.toml. It stops at the
// filesystem root. Returns the parsed project and the absolute path to the
// file, or ErrNotFound.
func Find(startDir string) (*Project, string, error) {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return nil, "", err
	}

	for {
		candidate := filepath.Join(dir, Filename)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			p, err := load(candidate)
			if err != nil {
				return nil, candidate, err
			}
			return p, candidate, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root.
			return nil, "", ErrNotFound
		}
		dir = parent
	}
}

func load(path string) (*Project, error) {
	var p Project
	if _, err := toml.DecodeFile(path, &p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if p.Namespace == "" {
		return nil, fmt.Errorf("%s: 'namespace' is required", path)
	}
	return &p, nil
}
