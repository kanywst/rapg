package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	password := "mysecretpassword"
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	keyBuf1 := DeriveKey([]byte(password), salt, DefaultKDFParams())
	defer keyBuf1.Destroy()
	key1 := keyBuf1.Bytes()

	keyBuf2 := DeriveKey([]byte(password), salt, DefaultKDFParams())
	defer keyBuf2.Destroy()
	key2 := keyBuf2.Bytes()

	if !bytes.Equal(key1, key2) {
		t.Error("DeriveKey should be deterministic with same inputs")
	}

	salt2, _ := GenerateSalt()
	keyBuf3 := DeriveKey([]byte(password), salt2, DefaultKDFParams())
	defer keyBuf3.Destroy()
	key3 := keyBuf3.Bytes()

	if bytes.Equal(key1, key3) {
		t.Error("DeriveKey should produce different keys for different salts")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	// simple key for testing
	copy(key, []byte("12345678901234567890123456789012"))

	plaintext := []byte("secret data")

	ciphertext, err := EncryptAESGCM(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptAESGCM failed: %v", err)
	}

	decrypted, err := DecryptAESGCM(ciphertext, key)
	if err != nil {
		t.Fatalf("DecryptAESGCM failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted data does not match plaintext. Got %s, want %s", decrypted, plaintext)
	}
}

func TestEncryptDecrypt_InvalidKey(t *testing.T) {
	key := make([]byte, 32)
	copy(key, []byte("12345678901234567890123456789012"))
	plaintext := []byte("data")

	ciphertext, _ := EncryptAESGCM(plaintext, key)

	wrongKey := make([]byte, 32)
	copy(wrongKey, []byte("22345678901234567890123456789012"))

	_, err := DecryptAESGCM(ciphertext, wrongKey)
	if err == nil {
		t.Error("Decrypt should fail with wrong key")
	}
}

func TestVerifyKey(t *testing.T) {
	key := []byte("somekey")
	hash := HashKey(key)

	if !VerifyKey(key, hash) {
		t.Error("VerifyKey should return true for matching key and hash")
	}

	wrongKey := []byte("otherkey")
	if VerifyKey(wrongKey, hash) {
		t.Error("VerifyKey should return false for non-matching key")
	}
}
