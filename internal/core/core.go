package core

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/awnumar/memguard"
	"github.com/kanywst/rapg/internal/config"
	"github.com/kanywst/rapg/internal/crypto"
	"github.com/kanywst/rapg/internal/storage"
)

var (
	// SessionKey holds the decrypted master key in protected memory.
	SessionKey *memguard.LockedBuffer
)

// IsInitialized checks if the vault has been set up.
func IsInitialized() bool {
	_, err := storage.GetMeta("salt")
	return err == nil
}

// InitializeVault sets up a new master password.
func InitializeVault(password []byte) error {
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return err
	}

	params := crypto.DefaultKDFParams()
	keyBuf := crypto.DeriveKey(password, salt, params)
	// We don't defer Destroy() here because we transfer ownership to SessionKey at the end.
	// If an error occurs, we must destroy it manually.

	hash := crypto.HashKey(keyBuf.Bytes())

	if err := storage.SaveMeta("salt", salt); err != nil {
		keyBuf.Destroy()
		return err
	}
	if err := storage.SaveMeta("validation", hash); err != nil {
		keyBuf.Destroy()
		return err
	}
	if err := storage.SaveMeta("argon_time", []byte(fmt.Sprintf("%d", params.Time))); err != nil {
		keyBuf.Destroy()
		return err
	}
	if err := storage.SaveMeta("argon_memory", []byte(fmt.Sprintf("%d", params.Memory))); err != nil {
		keyBuf.Destroy()
		return err
	}
	if err := storage.SaveMeta("argon_threads", []byte(fmt.Sprintf("%d", params.Threads))); err != nil {
		keyBuf.Destroy()
		return err
	}

	// Move key to protected memory (SessionKey takes ownership)
	if SessionKey != nil {
		SessionKey.Destroy()
	}
	SessionKey = keyBuf
	return nil
}

// UnlockVault attempts to derive the key and verify it.
func UnlockVault(password []byte) error {
	salt, err := storage.GetMeta("salt")
	if err != nil {
		return errors.New("vault not initialized")
	}

	expectedHash, err := storage.GetMeta("validation")
	if err != nil {
		return errors.New("vault corruption: missing validation hash")
	}

	// Load KDF params from storage, falling back to defaults if not found
	params := crypto.DefaultKDFParams()
	if t, err := storage.GetMeta("argon_time"); err == nil {
		if val, err := strconv.ParseUint(string(t), 10, 32); err == nil {
			params.Time = uint32(val)
		}
	}
	if m, err := storage.GetMeta("argon_memory"); err == nil {
		if val, err := strconv.ParseUint(string(m), 10, 32); err == nil {
			params.Memory = uint32(val)
		}
	}
	if th, err := storage.GetMeta("argon_threads"); err == nil {
		if val, err := strconv.ParseUint(string(th), 10, 8); err == nil {
			params.Threads = uint8(val)
		}
	}

	keyBuf := crypto.DeriveKey(password, salt, params)
	// If verification fails, we destroy the buffer.
	// If success, we transfer ownership to SessionKey.

	if !crypto.VerifyKey(keyBuf.Bytes(), expectedHash) {
		keyBuf.Destroy()
		return errors.New("invalid password")
	}

	if SessionKey != nil {
		SessionKey.Destroy()
	}
	SessionKey = keyBuf
	return nil
}

// LockVault destroys the session key.
func LockVault() {
	if SessionKey != nil {
		SessionKey.Destroy()
		SessionKey = nil
	}
}

// GenerateRandomPassword creates a cryptographically secure random password.
func GenerateRandomPassword(length int) (string, error) {
	const letters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()-_=+[]{}|;:,.<>?"
	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}
	return string(ret), nil
}

// AddEntry encrypts and stores a password. namespace may be empty
// (means "global" / visible without a project config).
func AddEntry(namespace, service, username string, data storage.SecretData) error {
	if SessionKey == nil {
		return errors.New("vault locked")
	}
	return storage.Create(namespace, service, username, data, SessionKey.Bytes(), crypto.EncryptAESGCM)
}

// GetEntry returns the decrypted secret data.
func GetEntry(entry storage.PasswordEntry) (*storage.SecretData, error) {
	if SessionKey == nil {
		return nil, errors.New("vault locked")
	}

	// SessionKey.Bytes() returns a slice referencing the protected memory.
	// It is only valid as long as SessionKey is not destroyed.
	decrypted, err := crypto.DecryptAESGCM(entry.Cipher, SessionKey.Bytes())
	if err != nil {
		return nil, err
	}

	var data storage.SecretData
	if err := json.Unmarshal(decrypted, &data); err != nil {
		return nil, fmt.Errorf("decrypt: malformed secret payload: %w", err)
	}

	return &data, nil
}

// GetEnvVars retrieves the env-tagged secrets that should be injected into
// a child process for the given project context.
//
// - project == nil   → only entries with an empty Namespace ('global').
// - project != nil   → only entries whose Namespace matches project.Namespace,
//                      filtered further by project.Allows(EnvKey).
//
// This deliberately scopes secrets: an entry tagged for project A must never
// leak into a run that has no project config or has project B's config.
func GetEnvVars(project *config.Project) (map[string]string, error) {
	if SessionKey == nil {
		return nil, errors.New("vault locked")
	}

	entries, err := storage.List()
	if err != nil {
		return nil, err
	}

	envVars := make(map[string]string)
	for _, entry := range entries {
		if project == nil {
			if entry.Namespace != "" {
				continue
			}
		} else {
			if entry.Namespace != project.Namespace {
				continue
			}
		}

		secret, err := GetEntry(entry)
		if err != nil || secret.EnvKey == "" {
			continue
		}
		if project != nil && !project.Allows(secret.EnvKey) {
			continue
		}
		envVars[secret.EnvKey] = secret.Password
	}
	return envVars, nil
}

func ListEntries() ([]storage.PasswordEntry, error) {
	return storage.List()
}

func DeleteEntry(id uint) error {
	return storage.Delete(id)
}
