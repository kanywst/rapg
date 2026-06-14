package main

import (
	"slices"
	"strings"
	"testing"
)

func envValue(environ []string, key string) (string, bool) {
	for _, e := range environ {
		k, v, _ := strings.Cut(e, "=")
		if k == key {
			return v, true
		}
	}
	return "", false
}

func TestChildEnvironStripsRealKey(t *testing.T) {
	// The parent shell already exports the real provider key — the exact
	// leak the proxy must prevent.
	parent := []string{
		"PATH=/usr/bin",
		"ANTHROPIC_API_KEY=sk-ant-REAL",
		"HOME=/home/dev",
	}
	override := map[string]string{
		"ANTHROPIC_BASE_URL":   "http://127.0.0.1:5000",
		"ANTHROPIC_AUTH_TOKEN": "proxy-token",
		"DATABASE_URL":         "postgres://x",
	}

	child := childEnviron(parent, override, "ANTHROPIC_API_KEY")

	if _, ok := envValue(child, "ANTHROPIC_API_KEY"); ok {
		t.Fatal("real ANTHROPIC_API_KEY leaked to the child env")
	}
	if v, _ := envValue(child, "ANTHROPIC_AUTH_TOKEN"); v != "proxy-token" {
		t.Errorf("ANTHROPIC_AUTH_TOKEN = %q, want proxy-token", v)
	}
	if v, _ := envValue(child, "ANTHROPIC_BASE_URL"); v != "http://127.0.0.1:5000" {
		t.Errorf("ANTHROPIC_BASE_URL = %q", v)
	}
	if v, _ := envValue(child, "DATABASE_URL"); v != "postgres://x" {
		t.Errorf("DATABASE_URL = %q, want it injected", v)
	}
	// Unrelated parent vars pass through.
	if v, _ := envValue(child, "PATH"); v != "/usr/bin" {
		t.Errorf("PATH = %q, want passthrough", v)
	}
}

func TestChildEnvironOverrideWins(t *testing.T) {
	// A parent var with the same name as an injected secret must be replaced,
	// not duplicated.
	parent := []string{"DATABASE_URL=postgres://STALE"}
	child := childEnviron(parent, map[string]string{"DATABASE_URL": "postgres://fresh"})

	count := 0
	for _, e := range child {
		if strings.HasPrefix(e, "DATABASE_URL=") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("DATABASE_URL appears %d times, want exactly 1", count)
	}
	if !slices.Contains(child, "DATABASE_URL=postgres://fresh") {
		t.Error("injected DATABASE_URL did not win over the parent value")
	}
}

func TestChildEnvironIgnoresEmptyStrip(t *testing.T) {
	// An empty strip key (e.g. a provider with no default) must not nuke
	// malformed-looking entries.
	parent := []string{"PATH=/usr/bin"}
	child := childEnviron(parent, nil, "")
	if !slices.Contains(child, "PATH=/usr/bin") {
		t.Error("empty strip key should be a no-op")
	}
}
