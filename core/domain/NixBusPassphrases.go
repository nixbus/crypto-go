package domain

type Passphrase struct {
	Version string
	Phrase  string
}

type NixBusPassphrases interface {
	GetByVersion(version string) (Passphrase, error)

	GetDefault() (Passphrase, error)

	Put(passphrase Passphrase)
}
