package core

import (
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/awnumar/memguard"
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

// AddEntry encrypts and stores a password.
func AddEntry(service, username string, data storage.SecretData) error {
	if SessionKey == nil {
		return errors.New("vault locked")
	}
	return storage.Create(service, username, data, SessionKey.Bytes(), crypto.EncryptAESGCM)
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

// GetEnvVars retrieves all secrets that have an EnvKey set.
func GetEnvVars() (map[string]string, error) {
	if SessionKey == nil {
		return nil, errors.New("vault locked")
	}

	entries, err := storage.List()
	if err != nil {
		return nil, err
	}

	envVars := make(map[string]string)
	for _, entry := range entries {
		secret, err := GetEntry(entry)
		if err != nil {
			continue // Skip corrupted entries
		}
		if secret.EnvKey != "" {
			envVars[secret.EnvKey] = secret.Password
		}
	}
	return envVars, nil
}

func ListEntries() ([]storage.PasswordEntry, error) {
	return storage.List()
}

func DeleteEntry(id uint) error {
	return storage.Delete(id)
}

// ImportCSV reads a CSV file and imports passwords.
func ImportCSV(r io.Reader) (int, error) {
	if SessionKey == nil {
		return 0, errors.New("vault locked")
	}

	reader := csv.NewReader(r)
	header, err := reader.Read()
	if err != nil {
		return 0, err
	}

	colMap := make(map[string]int)
	for i, h := range header {
		h = strings.ToLower(strings.TrimSpace(h))
		switch h {
		case "service", "url", "name", "title", "app":
			if _, ok := colMap["service"]; !ok {
				colMap["service"] = i
			}
		case "username", "user", "login", "email":
			if _, ok := colMap["username"]; !ok {
				colMap["username"] = i
			}
		case "password", "pass", "secret":
			if _, ok := colMap["password"]; !ok {
				colMap["password"] = i
			}
		case "notes", "note", "description", "comment":
			if _, ok := colMap["notes"]; !ok {
				colMap["notes"] = i
			}
		}
	}

	if _, ok := colMap["service"]; !ok {
		return 0, errors.New("could not find 'service', 'url', or 'name' column in CSV header")
	}
	if _, ok := colMap["password"]; !ok {
		return 0, errors.New("could not find 'password' column in CSV header")
	}

	count := 0
	rowNumber := 0
	var importError error
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		rowNumber++
		if err != nil {
			fmt.Fprintf(os.Stderr, "Skipping malformed CSV row %d: %v\n", rowNumber, err)
			importError = errors.New("one or more rows failed to parse")
			continue
		}

		service := record[colMap["service"]]
		pass := record[colMap["password"]]

		username := ""
		if idx, ok := colMap["username"]; ok && idx < len(record) {
			username = record[idx]
		}
		if username == "" {
			username = fmt.Sprintf("imported-%d", rowNumber)
		}

		notes := ""
		if idx, ok := colMap["notes"]; ok && idx < len(record) {
			notes = record[idx]
		}

		data := storage.SecretData{
			Password: pass,
			Notes:    notes,
		}

		if err := AddEntry(service, username, data); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to import %s: %v\n", service, err)
			importError = errors.New("one or more entries failed to import")
		} else {
			count++
		}
	}

	return count, importError
}

type AuditResult struct {
	Password string
	Count    int
	Services []string
}

// AuditPasswords checks for reused passwords across the vault.
// It uses a map to achieve O(n) performance, accepting the temporary memory overhead
// of holding plaintext passwords during the audit process.
func AuditPasswords() ([]AuditResult, error) {
	if SessionKey == nil {
		return nil, errors.New("vault locked")
	}

	entries, err := storage.List()
	if err != nil {
		return nil, err
	}

	// Map of password to list of services using it.
	passwordToServices := make(map[string][]string)

	for _, entry := range entries {
		secret, err := GetEntry(entry)
		if err != nil || secret.Password == "" {
			continue // Skip corrupted or empty passwords
		}
		serviceInfo := fmt.Sprintf("%s (%s)", entry.Service, entry.Username)
		passwordToServices[secret.Password] = append(passwordToServices[secret.Password], serviceInfo)
	}

	var results []AuditResult
	for pass, services := range passwordToServices {
		if len(services) > 1 {
			results = append(results, AuditResult{
				Password: pass,
				Count:    len(services),
				Services: services,
			})
		}
	}

	return results, nil
}
