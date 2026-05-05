// Package redact masks vault values appearing in arbitrary text — typically
// agent transcripts (Claude Code, Cursor, Aider) before sharing them in bug
// reports or pasting into chat. The package itself is pure: it takes a
// list of (value, label) pairs and a haystack, and returns the haystack with
// every value occurrence replaced by '[REDACTED:<label>]'.
//
// Two safety rules:
//
//   - Values shorter than MinLength characters are skipped. A vault entry
//     with password "test" would otherwise mask every "test" in the text.
//   - Longer values are processed before shorter ones, so a value contained
//     inside another value doesn't get partially shadowed.
package redact

import (
	"sort"
	"strings"
)

// MinLength is the shortest secret value Redact will substitute. Anything
// shorter is treated as too generic to be a unique secret.
const MinLength = 8

// Secret is one (value, label) pair fed to Redact.
type Secret struct {
	// Value is the literal string to search for in the haystack.
	Value string
	// Label is what the mask reads — typically an env-key name like
	// "ANTHROPIC_API_KEY" or a service identifier. Goes into
	// "[REDACTED:<label>]".
	Label string
}

// Redact returns input with every occurrence of each Secret.Value replaced
// by "[REDACTED:<Label>]". Values shorter than MinLength are skipped.
// Returns the count of distinct values that actually matched.
func Redact(input string, secrets []Secret) (string, int) {
	// Sort by descending length so longer values are masked before any
	// shorter values they might contain. (Example: vault has both
	// "sk-ant-abc12345" and "abc12345" — without this ordering the second
	// pass would reach into the already-masked first match.)
	sorted := make([]Secret, 0, len(secrets))
	for _, s := range secrets {
		if len(s.Value) >= MinLength {
			sorted = append(sorted, s)
		}
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		return len(sorted[i].Value) > len(sorted[j].Value)
	})

	out := input
	matched := 0
	for _, s := range sorted {
		if !strings.Contains(out, s.Value) {
			continue
		}
		out = strings.ReplaceAll(out, s.Value, "[REDACTED:"+s.Label+"]")
		matched++
	}
	return out, matched
}
