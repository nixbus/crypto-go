# crypto-go

A Go library for encrypting and decrypting data using versioned passphrases and ciphers.

## Installation

```sh
go get github.com/nixbus/crypto-go
```

## Usage

```go
package main

import (
 "fmt"
 "github.com/nixbus/crypto-go/crypto"
 "github.com/nixbus/crypto-go/crypto/domain"
)

func main() {
 passphrases := []domain.Passphrase{
  {Version: "v1", Phrase: "your_secret_passphrase"},
 }
 // Create a new crypto instance
 c := crypto.CreateNixBusCrypto("v1", passphrases)

 // Encrypt data
 plaintext := []byte("Sensitive data here")
 encrypted, err := c.Encrypt(plaintext)
 if err != nil {
  panic(err)
 }
 fmt.Printf("Encrypted: %s\n", encrypted)

 // Decrypt data
 decrypted, err := c.Decrypt(encrypted)
 if err != nil {
  panic(err)
 }
 fmt.Printf("Decrypted: %s\n", decrypted)
}
```
