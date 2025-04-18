package crypto

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/nixbus/crypto-go/core/domain"
)

func complexObject() map[string]any {
	return map[string]any{
		"result": []any{
			map[string]any{
				"status": "disabled",
				"name": map[string]any{
					"first":  "Ardella",
					"middle": "Cameron",
					"last":   "Lindgren",
				},
				"username":    "Ardella-Lindgren",
				"password":    "FlPE5mDTenoh1Nn",
				"emails":      []string{"Levi64@example.com", "Joel7@gmail.com"},
				"phoneNumber": "1-739-201-0185",
				"location": map[string]any{
					"street":  "473 Althea Glen",
					"city":    "North Joaquin",
					"state":   "Connecticut",
					"country": "Bangladesh",
					"zip":     "17772-2173",
					"coordinates": map[string]any{
						"latitude":  60.6908,
						"longitude": -177.1275,
					},
				},
				"website": "https://linear-pita.com/",
				"domain":  "threadbare-biology.name",
				"job": map[string]any{
					"title":      "Direct Response Planner",
					"descriptor": "Product",
					"area":       "Interactions",
					"type":       "Facilitator",
					"company":    "Gibson, O'Hara and McClure",
				},
				"creditCard": map[string]any{
					"number": "3529-0090-8912-2623",
					"cvv":    "772",
					"issuer": "maestro",
				},
				"uuid":     "3299b629-37f1-4c0a-8d6d-f6cdb3a4f1ae",
				"objectId": "664f72f0932e55b4cf9e8305",
			},
			map[string]any{
				"status": "disabled",
				"name": map[string]any{
					"first":  "Erica",
					"middle": "Jordan",
					"last":   "Larkin",
				},
				"username":    "Erica-Larkin",
				"password":    "TIkCakFzOoXqyZd",
				"emails":      []string{"Bette_Weimann@example.com", "Stella_Rice0@example.com"},
				"phoneNumber": "357-344-0892 x667",
				"location": map[string]any{
					"street":  "3184 Rhiannon Vista",
					"city":    "Daxview",
					"state":   "Nebraska",
					"country": "Azerbaijan",
					"zip":     "80231-5064",
					"coordinates": map[string]any{
						"latitude":  -38.2938,
						"longitude": -88.1684,
					},
				},
				"website": "https://which-disaster.biz",
				"domain":  "wasteful-band.net",
				"job": map[string]any{
					"title":      "Investor Response Engineer",
					"descriptor": "District",
					"area":       "Operations",
					"type":       "Developer",
					"company":    "Bins, Luettgen and White",
				},
				"creditCard": map[string]any{
					"number": "6771-8996-2594-7378",
					"cvv":    "802",
					"issuer": "mastercard",
				},
				"uuid":     "13533d88-9833-4820-818c-f78e15d11fc3",
				"objectId": "664f72f0932e55b4cf9e8306",
			},
		},
	}
}

func TestNixBusCrypto_EncryptFormat(t *testing.T) {
	defaultPassphraseVersion := "v1"
	passphrases := []domain.Passphrase{
		{Version: defaultPassphraseVersion, Phrase: "a_passphrase"},
	}
	c := CreateNixBusCrypto(defaultPassphraseVersion, passphrases)

	obj := complexObject()
	original, _ := json.Marshal(obj)
	encrypted, err := c.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	parts := strings.Split(string(encrypted), ":")
	if len(parts) < 2 {
		t.Fatalf("Encrypted format invalid: %s", encrypted)
	}
	got := map[string]string{
		"passphraseVersion": parts[0],
		"cipherVersion":     parts[1],
	}
	if got["passphraseVersion"] != defaultPassphraseVersion {
		t.Errorf("Expected passphraseVersion %s, got %s", defaultPassphraseVersion, got["passphraseVersion"])
	}
	if got["cipherVersion"] != "nb-c1" {
		t.Errorf("Expected cipherVersion nb-c1, got %s", got["cipherVersion"])
	}
}

func TestNixBusCrypto_DecryptKnownCipher(t *testing.T) {
	defaultPassphraseVersion := "v1"
	passphrases := []domain.Passphrase{
		{Version: defaultPassphraseVersion, Phrase: "a_passphrase"},
	}
	c := CreateNixBusCrypto(defaultPassphraseVersion, passphrases)

	original, _ := json.Marshal(complexObject())
	encrypted := "v1:nb-c1:cXFla2drLfPem5XbOwHX9A==:iFNB4WWHfc6D/55Z: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"
	decrypted, err := c.Decrypt([]byte(encrypted))
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}

	var expectedObj, actualObj any
	if err := json.Unmarshal(original, &expectedObj); err != nil {
		t.Fatalf("Failed to unmarshal expected JSON: %v", err)
	}
	if err := json.Unmarshal(decrypted, &actualObj); err != nil {
		t.Fatalf("Failed to unmarshal decrypted JSON: %v", err)
	}
	if !reflect.DeepEqual(expectedObj, actualObj) {
		expectedStr, _ := json.Marshal(expectedObj)
		actualStr, _ := json.Marshal(actualObj)
		t.Errorf("Decrypt: expected %s, got %s", string(expectedStr), string(actualStr))
	}
}

func TestNixBusCrypto_Decrypt_PassphraseNotFound(t *testing.T) {
	original, _ := json.Marshal(complexObject())

	cryptoV2 := CreateNixBusCrypto("v2", []domain.Passphrase{
		{Version: "v2", Phrase: "a_passphrase"},
	})
	encrypted, err := cryptoV2.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	cryptoV3 := CreateNixBusCrypto("v3", []domain.Passphrase{
		{Version: "v3", Phrase: "another_passphrase"},
	})
	_, err = cryptoV3.Decrypt(encrypted)
	if !errors.Is(err, domain.PassphraseNotFound) {
		t.Errorf("Expected PassphraseNotFound error, got %v", err)
	}
}

func TestNixBusCrypto_Decrypt_AllPassphrases(t *testing.T) {
	original, _ := json.Marshal(complexObject())

	cryptoV2 := CreateNixBusCrypto("v2", []domain.Passphrase{
		{Version: "v2", Phrase: "a_passphrase"},
	})
	encrypted, err := cryptoV2.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	cryptoV3 := CreateNixBusCrypto("v3", []domain.Passphrase{
		{Version: "v2", Phrase: "a_passphrase"},
		{Version: "v3", Phrase: "another_passphrase"},
	})
	decrypted, err := cryptoV3.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}
	if !reflect.DeepEqual(decrypted, original) {
		t.Errorf("Decrypt: expected %s, got %s", string(original), string(decrypted))
	}
}
