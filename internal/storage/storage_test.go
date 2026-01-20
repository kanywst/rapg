package storage

import (
	"os"
	"testing"
)

// setupTestDB creates a temporary directory, sets HOME to it, and initializes the DB.
// It returns a cleanup function that should be deferred.
func setupTestDB(t *testing.T) func() {
	tmpDir := t.TempDir()

	// Mock HOME to point to temp dir
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)

	if err := InitDB(); err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	return func() {
		os.Setenv("HOME", originalHome)
		// DB cleanup if necessary (GORM usually handles connection pooling, but file cleanup is done by t.TempDir)
	}
}

func TestMetaOperations(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	key := "test_key"
	value := []byte("test_value")

	if err := SaveMeta(key, value); err != nil {
		t.Fatalf("SaveMeta failed: %v", err)
	}

	retrieved, err := GetMeta(key)
	if err != nil {
		t.Fatalf("GetMeta failed: %v", err)
	}

	if string(retrieved) != string(value) {
		t.Errorf("GetMeta returned %s, want %s", retrieved, value)
	}

	_, err = GetMeta("non_existent")
	if err == nil {
		t.Error("GetMeta should fail for non-existent key")
	}
}

func TestEntryOperations(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Mock encrypt function
	mockEncrypt := func(data, key []byte) ([]byte, error) {
		return data, nil // No actual encryption for storage test
	}

	svc := "google"
	user := "test@example.com"
	secret := SecretData{Password: "password123"}
	dummyKey := []byte("dummy")

	// Test Create
	if err := Create(svc, user, secret, dummyKey, mockEncrypt); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Test Find
	entry, err := Find(svc, user)
	if err != nil {
		t.Fatalf("Find failed: %v", err)
	}
	if entry.Service != svc || entry.Username != user {
		t.Errorf("Find returned incorrect entry: %+v", entry)
	}

	// Test List
	entries, err := List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("List should return 1 entry, got %d", len(entries))
	}

	// Test Delete
	if err := Delete(entry.ID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	entries, _ = List()
	if len(entries) != 0 {
		t.Errorf("List should return 0 entries after delete, got %d", len(entries))
	}
}
