package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
)

// Config for Argon2id
const (
	DefaultArgonTime    = 3
	DefaultArgonMemory  = 128 * 1024
	DefaultArgonThreads = 4
	keyLen              = 32
)

// KDFParams holds the parameters for Argon2id.
type KDFParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

// DefaultKDFParams returns the current recommended parameters.
func DefaultKDFParams() KDFParams {
	return KDFParams{
		Time:    DefaultArgonTime,
		Memory:  DefaultArgonMemory,
		Threads: DefaultArgonThreads,
	}
}

// DeriveKey generates a 32-byte key from a master password and salt using Argon2id.
// It returns the key in a LockedBuffer for security.
func DeriveKey(password []byte, salt []byte, params KDFParams) *memguard.LockedBuffer {
	key := argon2.IDKey(password, salt, params.Time, params.Memory, params.Threads, keyLen)
	return memguard.NewBufferFromBytes(key)
}

// GenerateSalt creates a random salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// EncryptAESGCM encrypts data using AES-256-GCM.
func EncryptAESGCM(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptAESGCM decrypts data using AES-256-GCM.
func DecryptAESGCM(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// VerifyMasterPassword checks if the derived key matches the stored validation hash.
// This allows us to check if the password is correct without storing the password or key.
func VerifyKey(key []byte, storedHash []byte) bool {
	h := sha256.Sum256(key)
	// Use constant-time comparison to prevent timing attacks.
	if len(h) != len(storedHash) {
		return false
	}
	return subtle.ConstantTimeCompare(h[:], storedHash) == 1
}

// HashKey creates a verification hash of the key.
func HashKey(key []byte) []byte {
	h := sha256.Sum256(key)
	return h[:]
}
