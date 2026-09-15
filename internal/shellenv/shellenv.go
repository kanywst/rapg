// Package shellenv renders a set of secrets as shell statements for a `cd`
// hook to eval.
//
// The hard part of direnv-style auto-injection is not adding variables, it is
// taking them away again. A hook that only ever exports leaves the last
// project's DATABASE_URL in your shell after you leave it, visible to whatever
// you run next, which is a leak of exactly the kind rapg exists to prevent. So
// every render starts by unsetting what the previous render exported, and ends
// by recording what this one did.
//
// The bookkeeping lives in one environment variable, TrackerVar, holding a
// space-separated list of the names currently injected. It holds names only,
// never values.
package shellenv

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// TrackerVar is the variable the hook uses to remember what it exported.
const TrackerVar = "RAPG_INJECTED"

// validName matches what a shell will accept as a variable name. Anything else
// is dropped rather than emitted: these strings end up inside `unset` and
// `export`, and a name is not a place where quoting can save you.
var validName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ErrUnknownShell is returned for a shell this package cannot render.
var ErrUnknownShell = fmt.Errorf("shellenv: unknown shell")

// Render returns the statements that move a shell from having `previous`
// injected to having `env` injected.
//
// The output is deterministic: names are sorted, so a hook that fires twice in
// the same directory produces identical text.
func Render(shell string, previous []string, env map[string]string) (string, error) {
	var unset func([]string) string
	var export func(name, value string) string

	switch shell {
	case "zsh", "bash":
		unset = func(names []string) string { return "unset " + strings.Join(names, " ") }
		export = func(name, value string) string {
			return fmt.Sprintf("export %s=%s", name, quotePOSIX(value))
		}
	case "fish":
		unset = func(names []string) string { return "set -e " + strings.Join(names, " ") }
		export = func(name, value string) string {
			return fmt.Sprintf("set -gx %s %s", name, quoteFish(value))
		}
	default:
		return "", fmt.Errorf("%w: %q", ErrUnknownShell, shell)
	}

	names := make([]string, 0, len(env))
	for name := range env {
		if validName.MatchString(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	// Only unset what this hook injected and is not re-injecting. Dropping the
	// re-injected ones avoids a window where the variable does not exist, and
	// unsetting a name we never set would clobber the user's own environment.
	stale := make([]string, 0, len(previous))
	for _, name := range previous {
		if !validName.MatchString(name) || slices.Contains(names, name) {
			continue
		}
		stale = append(stale, name)
	}
	sort.Strings(stale)

	var b strings.Builder
	if len(stale) > 0 {
		b.WriteString(unset(stale))
		b.WriteByte('\n')
	}
	for _, name := range names {
		b.WriteString(export(name, env[name]))
		b.WriteByte('\n')
	}

	// The tracker itself is a name, not a secret, so it is safe to export.
	// Clearing it when nothing is injected keeps `env | grep RAPG` quiet in a
	// shell that is not in a project.
	if len(names) == 0 {
		b.WriteString(unset([]string{TrackerVar}))
		b.WriteByte('\n')
	} else {
		b.WriteString(export(TrackerVar, strings.Join(names, " ")))
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// quotePOSIX wraps s in single quotes, which suppress every expansion sh
// performs. A single quote cannot appear inside them, so each one is closed,
// escaped and reopened.
func quotePOSIX(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// quoteFish wraps s in single quotes. fish differs from sh here: inside single
// quotes it still honours backslash before a quote or another backslash, so
// both need escaping.
func quoteFish(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	return "'" + r.Replace(s) + "'"
}
