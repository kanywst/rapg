package storage

import (
	"testing"
)

// setupTestDB creates a temporary directory, sets HOME to it, and initializes the DB.
// It returns a cleanup function that should be deferred.
func setupTestDB(t *testing.T) func() {
	t.Helper()
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	if err := InitDB(); err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	return func() {
		// Close the underlying *sql.DB so the sqlite file handle is released
		// before t.TempDir tries to remove the directory.
		if DB != nil {
			if sqlDB, err := DB.DB(); err == nil {
				_ = sqlDB.Close()
			}
			DB = nil
		}
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

	// Verify hard delete: the row must be gone even with Unscoped(), not just soft-deleted.
	var count int64
	if err := DB.Unscoped().Model(&PasswordEntry{}).Where("id = ?", entry.ID).Count(&count).Error; err != nil {
		t.Fatalf("Count after delete failed: %v", err)
	}
	if count != 0 {
		t.Errorf("Delete should hard-delete the row, but %d row(s) remain in the table", count)
	}
}
