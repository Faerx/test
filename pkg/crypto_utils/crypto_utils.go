package crypto_utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

type KeyDeConf struct {
	Pass []byte
	Salt []byte
}

func MkN(cr cipher.AEAD) ([]byte, error) {
	nance := make([]byte, cr.NonceSize())
	if _, err := rand.Read(nance); err != nil {
		return nil, fmt.Errorf("failed gen nana  %v", err)
	}
	return nance, nil
}
func Crypter(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed cipher block %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed cipher GCM %v", err)
	}
	return gcm, nil
}
func DerKey(conf KeyDeConf) ([]byte, error) {
	if len(conf.Pass) == 0 || len(conf.Salt) == 0 {
		return nil, fmt.Errorf("debil?")
	}

	return argon2.IDKey(conf.Pass, conf.Salt, 1, 64*1024, 4, 32), nil
}
