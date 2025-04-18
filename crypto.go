package crypto

import (
	"sync"

	"github.com/nixbus/crypto-go/core/domain"
	"github.com/nixbus/crypto-go/core/infrastructure"
)

type NixBusCrypto = domain.NixBusCrypto

var (
	nixBusCryptoInstance *domain.NixBusCrypto
	once                 sync.Once
)

func GetNixBusCrypto(defaultPassphraseVersion string, passphrases []domain.Passphrase) *domain.NixBusCrypto {
	once.Do(func() {
		nixBusCryptoInstance = CreateNixBusCrypto(defaultPassphraseVersion, passphrases)
	})
	return nixBusCryptoInstance
}

func CreateNixBusCrypto(defaultPassphraseVersion string, passphrases []domain.Passphrase) *domain.NixBusCrypto {
	passphraseStore := infrastructure.NewNixBusInMemoryPassphrases(
		infrastructure.NixBusInMemoryPassphrasesOptions{
			DefaultVersion: defaultPassphraseVersion,
		},
	)
	for _, p := range passphrases {
		passphraseStore.Put(p)
	}

	cipherV1 := infrastructure.NewNixBusCipherV1()
	ciphers := domain.NewNixBusCiphers(cipherV1)

	deps := domain.NixBusCryptoDeps{
		Passphrases: passphraseStore,
		Ciphers:     ciphers,
	}

	return domain.NewNixBusCrypto(deps)
}
