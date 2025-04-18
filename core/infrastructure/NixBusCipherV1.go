package infrastructure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"

	"github.com/nixbus/crypto-go/core/domain"
	"golang.org/x/crypto/pbkdf2"
)

type CipherData struct {
	PassphraseVersion string
	Version           string
	Data              []byte
	IV                []byte
	Salt              []byte
}

type NixBusCipherV1 struct {
	version   string
	keyCache  map[string][]byte
	cacheLock sync.RWMutex
}

func NewNixBusCipherV1() *NixBusCipherV1 {
	return &NixBusCipherV1{
		version:   "nb-c1",
		keyCache:  make(map[string][]byte),
		cacheLock: sync.RWMutex{},
	}
}

func (n *NixBusCipherV1) Decrypt(text string, passphrase domain.Passphrase) (string, error) {
	ed, err := n.deserialize(text)
	if err != nil {
		return "", err
	}

	phrase := passphrase.Phrase
	salt := ed.Salt
	iv := ed.IV
	data := ed.Data

	key, err := n.deriveKey(phrase, salt)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	decrypted, err := aesgcm.Open(nil, iv, data, nil)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

func (n *NixBusCipherV1) Encrypt(text string, passphrase domain.Passphrase) (string, error) {
	phrase := passphrase.Phrase
	passphraseVersion := passphrase.Version

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key, err := n.deriveKey(phrase, salt)
	if err != nil {
		return "", err
	}

	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	encrypted := aesgcm.Seal(nil, iv, []byte(text), nil)

	result, err := n.serialize(CipherData{
		PassphraseVersion: passphraseVersion,
		Version:           n.version,
		Data:              encrypted,
		IV:                iv,
		Salt:              salt,
	})
	if err != nil {
		return "", err
	}

	return result, nil
}

func (n *NixBusCipherV1) GetVersion() string {
	return n.version
}

func (n *NixBusCipherV1) deserialize(text string) (CipherData, error) {
	parts := strings.Split(text, ":")
	if len(parts) != 5 {
		return CipherData{}, domain.CipherEncryptedDataNotValid
	}

	if parts[1] != n.version {
		return CipherData{}, domain.CipherNotFound
	}

	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return CipherData{}, domain.CipherEncryptedDataNotValid
	}

	iv, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return CipherData{}, domain.CipherEncryptedDataNotValid
	}

	data, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return CipherData{}, domain.CipherEncryptedDataNotValid
	}

	return CipherData{
		PassphraseVersion: parts[0],
		Version:           parts[1],
		Salt:              salt,
		IV:                iv,
		Data:              data,
	}, nil
}

func (n *NixBusCipherV1) serialize(ed CipherData) (string, error) {
	passphraseVersion := ed.PassphraseVersion
	version := ed.Version
	salt := base64.StdEncoding.EncodeToString(ed.Salt)
	iv := base64.StdEncoding.EncodeToString(ed.IV)
	data := base64.StdEncoding.EncodeToString(ed.Data)

	return fmt.Sprintf("%s:%s:%s:%s:%s", passphraseVersion, version, salt, iv, data), nil
}

func (n *NixBusCipherV1) deriveKey(passphrase string, salt []byte) ([]byte, error) {
	cacheKey := fmt.Sprintf("%s:%s", passphrase, base64.StdEncoding.EncodeToString(salt))

	n.cacheLock.RLock()
	cachedKey, exists := n.keyCache[cacheKey]
	n.cacheLock.RUnlock()

	if exists {
		return cachedKey, nil
	}

	key := pbkdf2.Key([]byte(passphrase), salt, 1000, 32, sha256.New)

	n.cacheLock.Lock()
	n.keyCache[cacheKey] = key
	n.cacheLock.Unlock()

	return key, nil
}
