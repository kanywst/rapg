package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// StaleAfter is how long a secret may go without rotation before rapg
// surfaces a freshness reminder. Static dev credentials don't auto-rotate
// (2026 guidance pushes short-lived/rotated creds), so this is a nudge, not
// enforcement.
const StaleAfter = 90 * 24 * time.Hour

// SecretData is the structure that gets serialized and encrypted.
type SecretData struct {
	Password string `json:"password"`
	TOTP     string `json:"totp,omitempty"`
	Notes    string `json:"notes,omitempty"`
	Url      string `json:"url,omitempty"`
	EnvKey   string `json:"env_key,omitempty"`
	// RotatedAt is when the password was last set or rotated. Zero for
	// entries created before rotation tracking existed — callers treat that
	// as "unknown", not "fresh".
	RotatedAt time.Time `json:"rotated_at,omitzero"`
}

// RotationAge reports how long ago the secret was last set/rotated relative
// to now. ok is false when RotatedAt is zero (legacy entries predating
// rotation tracking), letting callers distinguish "fresh" from "unknown".
func (d SecretData) RotationAge(now time.Time) (age time.Duration, ok bool) {
	if d.RotatedAt.IsZero() {
		return 0, false
	}
	return now.Sub(d.RotatedAt), true
}

// IsStale reports whether the secret is older than StaleAfter. Entries with
// an unknown rotation time are never reported stale — we don't nag about
// data we can't date.
func (d SecretData) IsStale(now time.Time) bool {
	age, ok := d.RotationAge(now)
	return ok && age > StaleAfter
}

// PasswordEntry is one row in the vault. Namespace scopes the entry to a
// project (matched by .rapg.toml). An empty Namespace means "global" — visible
// to any `rapg run` invocation that has no project config.
type PasswordEntry struct {
	gorm.Model
	Namespace string `gorm:"uniqueIndex:idx_namespace_service_username,priority:1"`
	Service   string `gorm:"uniqueIndex:idx_namespace_service_username,priority:2"`
	Username  string `gorm:"uniqueIndex:idx_namespace_service_username,priority:3"`
	// Cipher contains the encrypted JSON of SecretData.
	Cipher []byte
}

type Meta struct {
	Key   string `gorm:"primaryKey"`
	Value []byte
}

var DB *gorm.DB

func InitDB() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configDir := filepath.Join(home, ".rapg")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}

	dbPath := filepath.Join(configDir, "rapg.db")

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := db.AutoMigrate(&PasswordEntry{}, &Meta{}); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	// Pre-v4 schemas had a unique index on (Service, Username). v4 widens
	// uniqueness to (Namespace, Service, Username) so the same Service can
	// exist in multiple project namespaces. Drop the legacy index if present.
	// IF EXISTS makes it a no-op on fresh DBs; any other error (lock,
	// corruption) is surfaced as a startup warning so it isn't silently
	// swallowed.
	if err := db.Exec("DROP INDEX IF EXISTS idx_service_username").Error; err != nil {
		fmt.Fprintf(os.Stderr, "[rapg] warning: could not drop legacy idx_service_username: %v\n", err)
	}

	DB = db
	return nil
}

// Meta Operations (for Salt and Validation Hash)

func SaveMeta(key string, value []byte) error {
	return DB.Save(&Meta{Key: key, Value: value}).Error
}

func GetMeta(key string) ([]byte, error) {
	var m Meta
	if err := DB.First(&m, "key = ?", key).Error; err != nil {
		return nil, err
	}
	return m.Value, nil
}

// Entry Operations

func Create(namespace, service, username string, secret SecretData, key []byte, encryptFunc func([]byte, []byte) ([]byte, error)) error {
	// #nosec G117 -- The marshaled struct contains a "Password" field but
	// it is immediately encrypted with AES-256-GCM by encryptFunc on the
	// next line. Plaintext never leaves this stack frame.
	jsonData, err := json.Marshal(secret)
	if err != nil {
		return err
	}

	encrypted, err := encryptFunc(jsonData, key)
	if err != nil {
		return err
	}

	entry := PasswordEntry{
		Namespace: namespace,
		Service:   service,
		Username:  username,
		Cipher:    encrypted,
	}
	return DB.Create(&entry).Error
}

func List() ([]PasswordEntry, error) {
	var entries []PasswordEntry
	result := DB.Find(&entries)
	return entries, result.Error
}

func Delete(id uint) error {
	// Unscoped() forces a hard delete. The default GORM behavior for models
	// embedding gorm.Model is a soft delete (sets deleted_at), which would
	// leave the encrypted blob and metadata on disk — unacceptable for a
	// secret manager.
	return DB.Unscoped().Delete(&PasswordEntry{}, id).Error
}

func Find(namespace, service, username string) (*PasswordEntry, error) {
	var entry PasswordEntry
	if err := DB.Where("namespace = ? AND service = ? AND username = ?", namespace, service, username).First(&entry).Error; err != nil {
		return nil, err
	}
	return &entry, nil
}

// FindByID returns a single entry by its primary key. Used by callers that
// already hold an ID (e.g., the TUI selection list) and don't need to
// re-query by composite keys that are no longer globally unique.
func FindByID(id uint) (*PasswordEntry, error) {
	var entry PasswordEntry
	if err := DB.First(&entry, id).Error; err != nil {
		return nil, err
	}
	return &entry, nil
}
