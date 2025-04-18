package domain

type NixBusCiphers struct {
	defaultCipher NixBusCipher
	ciphers       map[string]NixBusCipher
}

func NewNixBusCiphers(defaultCipher NixBusCipher) *NixBusCiphers {
	ciphers := make(map[string]NixBusCipher)
	ciphers[defaultCipher.GetVersion()] = defaultCipher

	return &NixBusCiphers{
		defaultCipher: defaultCipher,
		ciphers:       ciphers,
	}
}

func (n *NixBusCiphers) GetByVersion(version string) (NixBusCipher, error) {
	cipher, exists := n.ciphers[version]
	if !exists {
		return nil, CipherNotFound
	}
	return cipher, nil
}

func (n *NixBusCiphers) GetDefault() NixBusCipher {
	return n.defaultCipher
}
