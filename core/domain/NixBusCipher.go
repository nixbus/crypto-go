package domain

type NixBusCipher interface {
	Encrypt(text string, passphrase Passphrase) (string, error)

	Decrypt(text string, passphrase Passphrase) (string, error)

	GetVersion() string
}
