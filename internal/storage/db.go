package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// SecretData is the structure that gets serialized and encrypted.
type SecretData struct {
	Password string `json:"password"`
	TOTP     string `json:"totp,omitempty"`
	Notes    string `json:"notes,omitempty"`
	Url      string `json:"url,omitempty"`
	EnvKey   string `json:"env_key,omitempty"`
}

type PasswordEntry struct {
	gorm.Model
	Service  string `gorm:"uniqueIndex:idx_service_username"`
	Username string `gorm:"uniqueIndex:idx_service_username"`
	// Cipher contains the encrypted JSON of SecretData
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

func Create(service, username string, secret SecretData, key []byte, encryptFunc func([]byte, []byte) ([]byte, error)) error {
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
		Service:  service,
		Username: username,
		Cipher:   encrypted,
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

func Find(service, username string) (*PasswordEntry, error) {
	var entry PasswordEntry
	if err := DB.Where("service = ? AND username = ?", service, username).First(&entry).Error; err != nil {
		return nil, err
	}
	return &entry, nil
}
