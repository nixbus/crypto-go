package domain

import (
	"strings"
)

type NixBusCryptoDeps struct {
	Passphrases NixBusPassphrases
	Ciphers     *NixBusCiphers
}

type NixBusCrypto struct {
	deps NixBusCryptoDeps
}

func NewNixBusCrypto(deps NixBusCryptoDeps) *NixBusCrypto {
	return &NixBusCrypto{
		deps: deps,
	}
}

func (n *NixBusCrypto) Encrypt(text []byte) ([]byte, error) {
	cipher := n.deps.Ciphers.GetDefault()
	passphrase, err := n.deps.Passphrases.GetDefault()
	if err != nil {
		return nil, err
	}

	encrypted, err := cipher.Encrypt(string(text), passphrase)
	if err != nil {
		return nil, err
	}

	return []byte(encrypted), nil
}

func (n *NixBusCrypto) Decrypt(text []byte) ([]byte, error) {
	encryptedText := string(text)

	parts := strings.Split(encryptedText, ":")
	if len(parts) != 5 {
		return nil, CipherEncryptedDataNotValid
	}

	passphraseVersion := parts[0]
	cipherVersion := parts[1]

	cipher, err := n.deps.Ciphers.GetByVersion(cipherVersion)
	if err != nil {
		return nil, err
	}

	passphrase, err := n.deps.Passphrases.GetByVersion(passphraseVersion)
	if err != nil {
		return nil, err
	}

	decrypted, err := cipher.Decrypt(encryptedText, passphrase)
	if err != nil {
		return nil, err
	}

	return []byte(decrypted), nil
}
