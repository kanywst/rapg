package audit

import (
	"os"
	"testing"
	"time"
)

func TestWriteAndRead_roundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	want := Session{
		Command:   "claude",
		Args:      []string{"code", "--print"},
		Namespace: "myapp",
		EnvKeys:   []string{"DB_URL", "ANTHROPIC_API_KEY"},
		ExitCode:  0,
		PID:       42,
		Cwd:       "/home/me/code/myapp",
	}
	if err := Write(want); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := Read(0)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Read returned %d entries, want 1", len(got))
	}
	g := got[0]
	if g.Command != want.Command || g.Namespace != want.Namespace || g.ExitCode != want.ExitCode {
		t.Errorf("scalar fields mismatch: %#v", g)
	}
	if len(g.EnvKeys) != 2 || g.EnvKeys[0] != "ANTHROPIC_API_KEY" || g.EnvKeys[1] != "DB_URL" {
		t.Errorf("EnvKeys not sorted on write: %#v", g.EnvKeys)
	}
	if g.Timestamp.IsZero() {
		t.Error("Write should default Timestamp to now")
	}
}

func TestRead_limitTakesTail(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	for i := range 5 {
		if err := Write(Session{Command: "echo", ExitCode: i, Timestamp: time.Now().UTC()}); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	got, err := Read(2)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Read(2) returned %d, want 2", len(got))
	}
	// Tail of 5 entries with ExitCode 0..4 → last two are 3, 4.
	if got[0].ExitCode != 3 || got[1].ExitCode != 4 {
		t.Errorf("Read(2) returned wrong tail: %v, %v", got[0].ExitCode, got[1].ExitCode)
	}
}

func TestRead_missingFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	got, err := Read(0)
	if err != nil {
		t.Fatalf("Read on missing file should not error: %v", err)
	}
	if got != nil {
		t.Errorf("Read on missing file should return nil, got %v", got)
	}
}

func TestRead_skipsMalformedLines(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := Write(Session{Command: "ok-1"}); err != nil {
		t.Fatal(err)
	}

	// Append a malformed line directly (writers other than us could in
	// theory corrupt the file).
	path, _ := LogPath()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("not json\n")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if err := Write(Session{Command: "ok-2"}); err != nil {
		t.Fatal(err)
	}

	got, err := Read(0)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 valid entries, got %d", len(got))
	}
	if got[0].Command != "ok-1" || got[1].Command != "ok-2" {
		t.Errorf("malformed line not skipped: %#v", got)
	}
}
