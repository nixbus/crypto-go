package domain

var (
	CipherNotFound              = NewDomainError("CipherNotFound")
	CipherEncryptedDataNotValid = NewDomainError("CipherEncryptedDataNotValid")
	PassphraseNotFound          = NewDomainError("PassphraseNotFound")
)
