package core

import (
	"testing"

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
	if err := AddEntry(svc, user, data); err != nil {
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

	AddEntry("db", "user", storage.SecretData{Password: "postgres://...", EnvKey: "DATABASE_URL"})
	AddEntry("api", "key", storage.SecretData{Password: "12345", EnvKey: "API_KEY"})
	AddEntry("other", "foo", storage.SecretData{Password: "ignored", EnvKey: ""})

	vars, err := GetEnvVars()
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
