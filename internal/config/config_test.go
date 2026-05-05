package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestFind_walksUp(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, Filename), "namespace = \"myapp\"\n")

	p, path, err := Find(deep)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if p.Namespace != "myapp" {
		t.Errorf("Namespace = %q, want %q", p.Namespace, "myapp")
	}
	if filepath.Dir(path) != root {
		t.Errorf("found at %q, want under %q", path, root)
	}
}

func TestFind_notFound(t *testing.T) {
	root := t.TempDir()
	_, _, err := Find(root)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestFind_missingNamespace(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, Filename), "keys = [\"X\"]\n")

	_, _, err := Find(root)
	if err == nil {
		t.Fatal("expected error for missing namespace, got nil")
	}
}

func TestAllows(t *testing.T) {
	cases := []struct {
		name string
		keys []string
		key  string
		want bool
	}{
		{"no whitelist allows everything", nil, "ANYTHING", true},
		{"empty whitelist allows everything", []string{}, "ANYTHING", true},
		{"whitelist hit", []string{"DB_URL", "API_KEY"}, "DB_URL", true},
		{"whitelist miss", []string{"DB_URL"}, "API_KEY", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Project{Keys: tc.keys}
			if got := p.Allows(tc.key); got != tc.want {
				t.Errorf("Allows(%q) = %v, want %v", tc.key, got, tc.want)
			}
		})
	}
}
