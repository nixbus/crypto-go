package infrastructure

import "github.com/nixbus/crypto-go/core/domain"

type NixBusInMemoryPassphrasesOptions struct {
	DefaultVersion string
}

type NixBusInMemoryPassphrases struct {
	options     NixBusInMemoryPassphrasesOptions
	passphrases map[string]domain.Passphrase
}

func NewNixBusInMemoryPassphrases(options NixBusInMemoryPassphrasesOptions) *NixBusInMemoryPassphrases {
	return &NixBusInMemoryPassphrases{
		options:     options,
		passphrases: make(map[string]domain.Passphrase),
	}
}

func (n *NixBusInMemoryPassphrases) GetByVersion(version string) (domain.Passphrase, error) {
	passphrase, exists := n.passphrases[version]
	if !exists {
		return domain.Passphrase{}, domain.PassphraseNotFound
	}
	return passphrase, nil
}

func (n *NixBusInMemoryPassphrases) GetDefault() (domain.Passphrase, error) {
	return n.GetByVersion(n.options.DefaultVersion)
}

func (n *NixBusInMemoryPassphrases) Put(passphrase domain.Passphrase) {
	n.passphrases[passphrase.Version] = passphrase
}
