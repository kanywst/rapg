package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

func EncryptAES(text, key, commonIV []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, commonIV)
	ciphertext := make([]byte, len(text))
	cfb.XORKeyStream(ciphertext, text)

	return ciphertext, nil
}

func DecryptAES(ciphertext, key, commonIV []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cfbdec := cipher.NewCFBDecrypter(block, commonIV)
	plaintext := make([]byte, len(ciphertext))
	cfbdec.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, err
	}
	return key, nil
}
