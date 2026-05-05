package core

import (
	"testing"

	"github.com/kanywst/rapg/internal/config"
	"github.com/kanywst/rapg/internal/storage"
)

func setupCoreTest(t *testing.T) func() {
	t.Helper()
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	if err := storage.InitDB(); err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	// Reset SessionKey
	if SessionKey != nil {
		SessionKey.Destroy()
		SessionKey = nil
	}

	return func() {
		if SessionKey != nil {
			SessionKey.Destroy()
			SessionKey = nil
		}
		// Release the sqlite file handle before t.TempDir cleanup runs.
		if storage.DB != nil {
			if sqlDB, err := storage.DB.DB(); err == nil {
				_ = sqlDB.Close()
			}
			storage.DB = nil
		}
	}
}

func TestVaultLifecycle(t *testing.T) {
	cleanup := setupCoreTest(t)
	defer cleanup()

	password := "masterpass"

	// 1. Initialize
	if IsInitialized() {
		t.Error("Vault should not be initialized initially")
	}

	if err := InitializeVault([]byte(password)); err != nil {
		t.Fatalf("InitializeVault failed: %v", err)
	}

	if !IsInitialized() {
		t.Error("Vault should be initialized after InitializeVault")
	}

	if SessionKey == nil {
		t.Error("SessionKey should be set after initialization")
	}

	// 2. Lock (Simulate by clearing key)
	SessionKey = nil

	// 3. Unlock with wrong password
	if err := UnlockVault([]byte("wrongpass")); err == nil {
		t.Error("UnlockVault should fail with wrong password")
	}

	// 4. Unlock with correct password
	if err := UnlockVault([]byte(password)); err != nil {
		t.Fatalf("UnlockVault failed with correct password: %v", err)
	}

	if SessionKey == nil {
		t.Error("SessionKey should be restored after unlock")
	}
}

func TestEntryManagement(t *testing.T) {
	cleanup := setupCoreTest(t)
	defer cleanup()

	InitializeVault([]byte("masterpass"))

	svc := "github"
	user := "octocat"
	pass := "secret123"

	data := storage.SecretData{
		Password: pass,
		Notes:    "my notes",
	}

	// Add
	if err := AddEntry("", svc, user, data); err != nil {
		t.Fatalf("AddEntry failed: %v", err)
	}

	// Verify storage directly (optional, but good for integration check)
	entries, _ := ListEntries()
	if len(entries) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(entries))
	}

	// Get (Decrypt)
	retrieved, err := GetEntry(entries[0])
	if err != nil {
		t.Fatalf("GetEntry failed: %v", err)
	}

	if retrieved.Password != pass {
		t.Errorf("Decrypted password mismatch. Got %s, want %s", retrieved.Password, pass)
	}
	if retrieved.Notes != "my notes" {
		t.Errorf("Decrypted notes mismatch")
	}
}

func TestEnvVars(t *testing.T) {
	cleanup := setupCoreTest(t)
	defer cleanup()
	InitializeVault([]byte("p"))

	AddEntry("", "db", "user", storage.SecretData{Password: "postgres://...", EnvKey: "DATABASE_URL"})
	AddEntry("", "api", "key", storage.SecretData{Password: "12345", EnvKey: "API_KEY"})
	AddEntry("", "other", "foo", storage.SecretData{Password: "ignored", EnvKey: ""})

	vars, err := GetEnvVars(nil)
	if err != nil {
		t.Fatalf("GetEnvVars failed: %v", err)
	}

	if len(vars) != 2 {
		t.Errorf("Expected 2 env vars, got %d", len(vars))
	}
	if vars["DATABASE_URL"] != "postgres://..." {
		t.Error("DATABASE_URL mismatch")
	}
}

func TestGetEnvVars_namespaceScoping(t *testing.T) {
	cleanup := setupCoreTest(t)
	defer cleanup()
	InitializeVault([]byte("p"))

	// Two namespaces + one global entry, all env-tagged.
	AddEntry("", "global-db", "u", storage.SecretData{Password: "g", EnvKey: "GLOBAL_KEY"})
	AddEntry("proj-a", "db", "u", storage.SecretData{Password: "a", EnvKey: "DB_URL"})
	AddEntry("proj-a", "anthropic", "u", storage.SecretData{Password: "ka", EnvKey: "ANTHROPIC_API_KEY"})
	AddEntry("proj-b", "db", "u", storage.SecretData{Password: "b", EnvKey: "DB_URL"})

	// nil project → only the global entry.
	got, err := GetEnvVars(nil)
	if err != nil {
		t.Fatalf("GetEnvVars(nil): %v", err)
	}
	if len(got) != 1 || got["GLOBAL_KEY"] != "g" {
		t.Errorf("nil project leaked or missed entries: %#v", got)
	}

	// proj-a, no whitelist → all proj-a env-tagged entries.
	got, err = GetEnvVars(&config.Project{Namespace: "proj-a"})
	if err != nil {
		t.Fatalf("GetEnvVars(proj-a): %v", err)
	}
	if len(got) != 2 || got["DB_URL"] != "a" || got["ANTHROPIC_API_KEY"] != "ka" {
		t.Errorf("proj-a got: %#v", got)
	}

	// proj-a with whitelist → only DB_URL passes.
	got, err = GetEnvVars(&config.Project{Namespace: "proj-a", Keys: []string{"DB_URL"}})
	if err != nil {
		t.Fatalf("GetEnvVars(proj-a, whitelist): %v", err)
	}
	if len(got) != 1 || got["DB_URL"] != "a" {
		t.Errorf("proj-a whitelist got: %#v", got)
	}

	// proj-b → its own DB_URL, not proj-a's.
	got, err = GetEnvVars(&config.Project{Namespace: "proj-b"})
	if err != nil {
		t.Fatalf("GetEnvVars(proj-b): %v", err)
	}
	if got["DB_URL"] != "b" {
		t.Errorf("proj-b DB_URL = %q, want %q", got["DB_URL"], "b")
	}
}

func TestGetEnvVars_inheritGlobal(t *testing.T) {
	cleanup := setupCoreTest(t)
	defer cleanup()
	InitializeVault([]byte("p"))

	// Global utility secret + proj-a secrets.
	AddEntry("", "github", "u", storage.SecretData{Password: "ghp_global", EnvKey: "GITHUB_TOKEN"})
	AddEntry("proj-a", "anthropic", "u", storage.SecretData{Password: "ka", EnvKey: "ANTHROPIC_API_KEY"})

	// Without inherit_global → only proj-a entries.
	got, err := GetEnvVars(&config.Project{Namespace: "proj-a"})
	if err != nil {
		t.Fatalf("GetEnvVars: %v", err)
	}
	if _, ok := got["GITHUB_TOKEN"]; ok {
		t.Errorf("global GITHUB_TOKEN leaked into strict-isolation run: %#v", got)
	}
	if got["ANTHROPIC_API_KEY"] != "ka" {
		t.Errorf("proj-a ANTHROPIC_API_KEY missing: %#v", got)
	}

	// With inherit_global → global GITHUB_TOKEN visible alongside proj-a.
	got, err = GetEnvVars(&config.Project{Namespace: "proj-a", InheritGlobal: true})
	if err != nil {
		t.Fatalf("GetEnvVars(inherit): %v", err)
	}
	if got["GITHUB_TOKEN"] != "ghp_global" {
		t.Errorf("inherited GITHUB_TOKEN missing or wrong: %#v", got)
	}
	if got["ANTHROPIC_API_KEY"] != "ka" {
		t.Errorf("proj-a ANTHROPIC_API_KEY missing: %#v", got)
	}
}

func TestGetEnvVars_inheritGlobal_projectOverridesGlobal(t *testing.T) {
	cleanup := setupCoreTest(t)
	defer cleanup()
	InitializeVault([]byte("p"))

	// Same env key in global and proj-a — project value must win.
	AddEntry("", "github", "u", storage.SecretData{Password: "ghp_GLOBAL", EnvKey: "GITHUB_TOKEN"})
	AddEntry("proj-a", "github", "u", storage.SecretData{Password: "ghp_PROJECT", EnvKey: "GITHUB_TOKEN"})

	got, err := GetEnvVars(&config.Project{Namespace: "proj-a", InheritGlobal: true})
	if err != nil {
		t.Fatalf("GetEnvVars: %v", err)
	}
	if got["GITHUB_TOKEN"] != "ghp_PROJECT" {
		t.Errorf("project value should override global on key collision; got %q", got["GITHUB_TOKEN"])
	}
}

func TestGenerateRandomPassword(t *testing.T) {
	p1, err := GenerateRandomPassword(16)
	if err != nil {
		t.Fatalf("GenerateRandomPassword failed: %v", err)
	}
	if len(p1) != 16 {
		t.Errorf("Expected length 16, got %d", len(p1))
	}

	p2, _ := GenerateRandomPassword(16)
	if p1 == p2 {
		t.Error("Random passwords should not be identical")
	}
}
