# crypto-go

A robust Go library for secure data encryption and decryption with support for versioned passphrases and ciphers. Built to provide a reliable way to protect sensitive data in Go applications.

## Features

- **Versioned Passphrases**: Manage multiple passphrases with version tracking
- **Cipher Versioning**: Support for different encryption algorithms with version control
- **In-Memory Passphrase Storage**: Secure storage of passphrases in memory
- **AES-GCM Encryption**: Industry-standard encryption with authenticated encryption
- **PBKDF2 Key Derivation**: Secure key derivation from passphrases
- **Key Caching**: Performance optimization for repeated encryption/decryption
- **Singleton Pattern**: Easy access to crypto instance throughout your application
- **Thread-safe**: Designed for concurrent access

## Installation

```sh
go get github.com/nixbus/crypto-go
```

Requires Go 1.23 or higher.

## Usage

### Basic Usage

```go
package main

import (
    "fmt"
    "github.com/nixbus/crypto-go/crypto"
    "github.com/nixbus/crypto-go/core/domain"
)

func main() {
    // Define passphrases with versions
    passphrases := []domain.Passphrase{
        {Version: "v1", Phrase: "your_secret_passphrase"},
    }
    
    // Create a new crypto instance with default passphrase version
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

### Using Multiple Passphrases

```go
// Define multiple passphrases with different versions
passphrases := []domain.Passphrase{
    {Version: "v1", Phrase: "old_passphrase"},
    {Version: "v2", Phrase: "new_passphrase"},
}

// Create crypto with v2 as default, but able to decrypt v1
c := crypto.CreateNixBusCrypto("v2", passphrases)

// Will encrypt with v2
newEncrypted, _ := c.Encrypt([]byte("data"))

// Can decrypt both v1 and v2 encrypted data
oldEncrypted := []byte("v1:nb-c1:...") // v1 encrypted data
c.Decrypt(oldEncrypted) // Works
c.Decrypt(newEncrypted) // Also works
```

### Singleton Pattern

```go
// Get or create singleton instance
c1 := crypto.GetNixBusCrypto("v1", passphrases)
c2 := crypto.GetNixBusCrypto("v1", passphrases)

// c1 and c2 reference the same instance
```

## Key Concepts

### Passphrase Versioning

Passphrases are versioned to allow for passphrase rotation while maintaining backward compatibility. The library can decrypt data encrypted with any known passphrase version, while encrypting new data with the default version.

### Cipher Structure

The encrypted data format follows this structure:
```
passphraseVersion:cipherVersion:salt:iv:encryptedData
```

For example:
```
v1:nb-c1:cXFla2drLfPem5XbOwHX9A==:iFNB4WWHfc6D/55Z:sNS1/yhyYuiTYNMpZDRbLA...
```

### Architecture

The library follows a clean architecture approach:

- **Domain Layer**: Core interfaces and entities (`NixBusCrypto`, `NixBusCipher`, etc.)
- **Infrastructure Layer**: Implementations of domain interfaces (`NixBusCipherV1`, `NixBusInMemoryPassphrases`)
- **API Layer**: Public interfaces for library consumers (`crypto` package)

### Security Considerations

- Passphrases should be kept secure and not hardcoded in your application
- For production use, consider using a secure secret management solution
- The library uses AES-GCM with PBKDF2 key derivation for strong security
