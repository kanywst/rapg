package crypto

import (
	"crypto/cipher"
)

type Block interface {
	BlockSize() int
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
}

func MakeEncrypt(c Block, text []byte, key []byte, commonIV []byte) ([]byte, error) {
	cfb := cipher.NewCFBEncrypter(c, commonIV)
	result := make([]byte, len(text))
	cfb.XORKeyStream(result, text)

	return result, nil
}

func MakeDecrypt(c Block, text []byte, key []byte, commonIV []byte) ([]byte, error) {
	cfbdec := cipher.NewCFBDecrypter(c, commonIV)
	result := make([]byte, len(text))
	cfbdec.XORKeyStream(result, text)

	return result, nil
}
