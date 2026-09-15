package shellenv

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestUnknownShellIsRejected(t *testing.T) {
	_, err := Render("csh", nil, map[string]string{"A": "b"})
	if !errors.Is(err, ErrUnknownShell) {
		t.Fatalf("err = %v, want ErrUnknownShell", err)
	}
}

// The whole reason this package exists: leaving a project has to take its
// secrets with it.
func TestLeavingAProjectUnsetsWhatWasInjected(t *testing.T) {
	got, err := Render("zsh", []string{"DATABASE_URL", "ANTHROPIC_API_KEY"}, nil)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	if !strings.Contains(got, "unset ANTHROPIC_API_KEY DATABASE_URL") {
		t.Errorf("did not unset the previous injection:\n%s", got)
	}
	if strings.Contains(got, "export DATABASE_URL") {
		t.Errorf("re-exported a variable while leaving:\n%s", got)
	}
	if !strings.Contains(got, "unset "+TrackerVar) {
		t.Errorf("did not clear the tracker:\n%s", got)
	}
}

// Moving between two projects must drop the old project's keys, not merge the
// two sets.
func TestMovingBetweenProjectsDropsTheOldKeys(t *testing.T) {
	got, err := Render("zsh",
		[]string{"OLD_ONLY", "SHARED"},
		map[string]string{"SHARED": "new", "NEW_ONLY": "x"},
	)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	if !strings.Contains(got, "unset OLD_ONLY") {
		t.Errorf("did not unset the old project's key:\n%s", got)
	}
	// SHARED is being re-exported, so unsetting it first would leave a window
	// where it does not exist for no reason.
	if strings.Contains(got, "unset OLD_ONLY SHARED") || strings.Contains(got, "unset SHARED") {
		t.Errorf("unset a variable it was about to re-export:\n%s", got)
	}
	if !strings.Contains(got, "export SHARED='new'") {
		t.Errorf("did not re-export SHARED with the new value:\n%s", got)
	}
}

// A variable rapg never injected must not be touched, even if it is named in
// the tracker. Unsetting the user's own PATH because something corrupted the
// tracker would be memorable for the wrong reasons.
func TestOnlyPreviouslyInjectedNamesAreUnset(t *testing.T) {
	got, err := Render("zsh", []string{"MY_OWN_VAR"}, map[string]string{"A": "1"})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	// This one *is* in the tracker, so it is ours to remove.
	if !strings.Contains(got, "unset MY_OWN_VAR") {
		t.Errorf("did not unset a tracked name:\n%s", got)
	}

	// Nothing outside the tracker appears at all.
	if strings.Contains(got, "PATH") || strings.Contains(got, "HOME") {
		t.Errorf("touched a variable that was never tracked:\n%s", got)
	}
}

// Names go into `unset` and `export` unquoted, so anything that is not a
// shell-legal identifier has to be dropped rather than emitted.
func TestIllegalNamesAreDropped(t *testing.T) {
	got, err := Render("zsh",
		[]string{"OK_OLD", "bad;rm -rf /"},
		map[string]string{
			"GOOD":              "1",
			"2LEADING_DIGIT":    "x",
			"has-dash":          "x",
			"semi;echo pwned":   "x",
			"$(touch /tmp/pwn)": "x",
		},
	)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	for _, bad := range []string{"rm -rf", "2LEADING_DIGIT", "has-dash", "echo pwned", "touch /tmp/pwn"} {
		if strings.Contains(got, bad) {
			t.Errorf("emitted an illegal name %q:\n%s", bad, got)
		}
	}
	if !strings.Contains(got, "export GOOD='1'") {
		t.Errorf("dropped the legal name too:\n%s", got)
	}
}

// Values are attacker-shaped by definition: they are whatever is in the vault,
// and the output is eval'd. Each of these runs the rendered text through the
// real shell and reads the variable back.
func TestValuesSurviveTheShellVerbatim(t *testing.T) {
	nasty := map[string]string{
		"SINGLE":    `it's here`,
		"DOUBLE":    `say "hi"`,
		"DOLLAR":    `$HOME and ${PATH}`,
		"BACKTICK":  "`id`",
		"SUBSHELL":  "$(id)",
		"SEMICOLON": "a; id",
		"NEWLINE":   "line1\nline2",
		"BACKSLASH": `back\slash`,
		"GLOB":      "*",
		"MIXED":     `'"$(id)`,
	}

	for _, shell := range []string{"bash", "zsh", "fish"} {
		bin, err := exec.LookPath(shell)
		if err != nil {
			t.Logf("skipping %s: not installed", shell)
			continue
		}

		t.Run(shell, func(t *testing.T) {
			rendered, err := Render(shell, nil, nasty)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}

			for name, want := range nasty {
				script := rendered + "\nprintf '%s' \"$" + name + "\"\n"
				out, err := exec.Command(bin, "-c", script).Output()
				if err != nil {
					t.Fatalf("%s rejected the script for %s: %v\n%s", shell, name, err, rendered)
				}
				if string(out) != want {
					t.Errorf("%s: %s = %q, want %q", shell, name, string(out), want)
				}
			}
		})
	}
}

// The same, for the unset path: a tracker full of junk must not become a
// command.
func TestRenderedUnsetIsInert(t *testing.T) {
	marker := "/tmp/rapg-shellenv-should-not-exist"
	_ = os.Remove(marker)

	rendered, err := Render("bash", []string{"A;touch " + marker, "B"}, nil)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	bin, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	if out, err := exec.Command(bin, "-c", rendered).CombinedOutput(); err != nil {
		t.Fatalf("bash rejected the script: %v\n%s\n%s", err, rendered, out)
	}

	if _, err := os.Stat(marker); err == nil {
		_ = os.Remove(marker)
		t.Fatal("a tracker entry executed a command")
	}
}

// Two renders of the same state must be byte-identical, or a prompt hook
// produces churn.
func TestRenderIsDeterministic(t *testing.T) {
	env := map[string]string{"C": "3", "A": "1", "B": "2"}
	first, err := Render("zsh", []string{"Z", "Y"}, env)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for i := range 20 {
		again, err := Render("zsh", []string{"Z", "Y"}, env)
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		if again != first {
			t.Fatalf("render %d differs:\n%s\nvs\n%s", i, again, first)
		}
	}
}

func TestTrackerRecordsExactlyWhatWasExported(t *testing.T) {
	got, err := Render("zsh", nil, map[string]string{"B": "2", "A": "1"})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(got, "export "+TrackerVar+"='A B'") {
		t.Errorf("tracker = wrong contents:\n%s", got)
	}
}
