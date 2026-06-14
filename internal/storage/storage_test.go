package storage

import (
	"encoding/json"
	"testing"
	"time"
)

func TestRotationAge(t *testing.T) {
	now := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)

	// Unknown (zero) rotation time: ok=false, never stale.
	var unknown SecretData
	if _, ok := unknown.RotationAge(now); ok {
		t.Error("zero RotatedAt should report ok=false")
	}
	if unknown.IsStale(now) {
		t.Error("untracked entry must never be reported stale")
	}

	// Fresh: one day old.
	fresh := SecretData{RotatedAt: now.Add(-24 * time.Hour)}
	age, ok := fresh.RotationAge(now)
	if !ok || age != 24*time.Hour {
		t.Errorf("RotationAge = %v, %v; want 24h, true", age, ok)
	}
	if fresh.IsStale(now) {
		t.Error("1-day-old entry should not be stale")
	}

	// Stale: older than StaleAfter.
	old := SecretData{RotatedAt: now.Add(-(StaleAfter + time.Hour))}
	if !old.IsStale(now) {
		t.Error("entry older than StaleAfter should be stale")
	}

	// Boundary: exactly StaleAfter old is not yet stale (strict >).
	edge := SecretData{RotatedAt: now.Add(-StaleAfter)}
	if edge.IsStale(now) {
		t.Error("entry exactly StaleAfter old should not yet be stale")
	}
}

func TestSecretDataRotatedAtRoundTrip(t *testing.T) {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	b, err := json.Marshal(SecretData{Password: "p", RotatedAt: ts})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var out SecretData
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if !out.RotatedAt.Equal(ts) {
		t.Errorf("RotatedAt round-trip = %v, want %v", out.RotatedAt, ts)
	}

	// Legacy payloads without the field must decode to the zero time, which
	// RotationAge treats as "unknown".
	var legacy SecretData
	if err := json.Unmarshal([]byte(`{"password":"p"}`), &legacy); err != nil {
		t.Fatalf("legacy unmarshal failed: %v", err)
	}
	if !legacy.RotatedAt.IsZero() {
		t.Errorf("missing rotated_at should be zero time, got %v", legacy.RotatedAt)
	}
}

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

	// Test Create (namespace empty = global)
	if err := Create("", svc, user, secret, dummyKey, mockEncrypt); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Test Find
	entry, err := Find("", svc, user)
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

func TestNamespaceUniqueness(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	noop := func(data, _ []byte) ([]byte, error) { return data, nil }
	secret := SecretData{Password: "x"}

	// Same (service, username) in two different namespaces must coexist.
	if err := Create("proj-a", "postgres", "app", secret, []byte("k"), noop); err != nil {
		t.Fatalf("Create in proj-a failed: %v", err)
	}
	if err := Create("proj-b", "postgres", "app", secret, []byte("k"), noop); err != nil {
		t.Fatalf("Create in proj-b should succeed across namespaces: %v", err)
	}

	// Same (namespace, service, username) must collide.
	if err := Create("proj-a", "postgres", "app", secret, []byte("k"), noop); err == nil {
		t.Error("Create with duplicate (namespace, service, username) should fail")
	}

	// Find scoped by namespace returns the right row.
	a, err := Find("proj-a", "postgres", "app")
	if err != nil {
		t.Fatalf("Find in proj-a failed: %v", err)
	}
	b, err := Find("proj-b", "postgres", "app")
	if err != nil {
		t.Fatalf("Find in proj-b failed: %v", err)
	}
	if a.ID == b.ID {
		t.Errorf("Find returned the same row across namespaces: %d", a.ID)
	}
}
