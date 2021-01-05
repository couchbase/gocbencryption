/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */
package gocbfieldcrypt

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestLegacyAesCryptoProvider(t *testing.T) {
	expected := "The old grey goose jumped over the wrickety gate."

	keyStore := &InsecureKeyring{
		keys: map[string]Key{
			"mypublickey": {
				ID:    "mypublickey",
				Bytes: []byte("!mysecretkey#9^5usdk39d&dlf)03sL"),
			},
			"myhmackey": {
				ID:    "myhmackey",
				Bytes: []byte("myauthpassword"),
			},
		},
	}

	provider := NewLegacyAes256CryptoProvider(keyStore, "mypublickey", "myhmackey")

	testEncDoc := map[string]interface{}{
		"alg":        "AES-256-HMAC-SHA256",
		"kid":        "mypublickey",
		"iv":         "Cfq84/46Qjet3EEQ1HUwSg==",
		"ciphertext": "sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==",
		"sig":        "rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM=",
	}

	b, err := provider.Decrypt(NewEncryptionResultFromMap(testEncDoc))
	if err != nil {
		t.Fatalf("Decrypt failed with error: %v", err)
	}

	var actual string
	err = json.Unmarshal(b, &actual)
	if err != nil {
		t.Fatalf("Unmarshal failed with error: %v", err)
	}

	if actual != expected {
		t.Fatalf("Expected message to be %s but was %s", expected, actual)
	}
}

func TestLegacyAesCryptoProvider_DecryptMissingKid(t *testing.T) {
	keyStore := &InsecureKeyring{
		keys: map[string]Key{
			"mypublickey": {
				ID:    "mypublickey",
				Bytes: []byte("!mysecretkey#9^5usdk39d&dlf)03sL"),
			},
			"myhmackey": {
				ID:    "myhmackey",
				Bytes: []byte("myauthpassword"),
			},
		},
	}

	provider := NewLegacyAes256CryptoProvider(keyStore, "mypublickey", "myhmackey")

	testEncDoc := map[string]interface{}{
		"alg":        "AES-256-HMAC-SHA256",
		"iv":         "Cfq84/46Qjet3EEQ1HUwSg==",
		"ciphertext": "sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==",
		"sig":        "rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM=",
	}

	_, err := provider.Decrypt(NewEncryptionResultFromMap(testEncDoc))
	if !errors.Is(err, ErrInvalidCryptoKey) {
		t.Fatalf("Decrypt should have failed with invalid crypto key, was: %v", err)
	}
}

func TestLegacyAesCryptoProvider_DecryptNotMatchingKid(t *testing.T) {
	keyStore := &InsecureKeyring{
		keys: map[string]Key{
			"mypublickey": {
				ID:    "mypublickey",
				Bytes: []byte("!mysecretkey#9^5usdk39d&dlf)03sL"),
			},
			"myhmackey": {
				ID:    "myhmackey",
				Bytes: []byte("myauthpassword"),
			},
		},
	}

	provider := NewLegacyAes256CryptoProvider(keyStore, "mypublickey", "myhmackey")

	testEncDoc := map[string]interface{}{
		"alg":        "AES-256-HMAC-SHA256",
		"kid":        "imwrong",
		"iv":         "Cfq84/46Qjet3EEQ1HUwSg==",
		"ciphertext": "sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==",
		"sig":        "rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM=",
	}

	_, err := provider.Decrypt(NewEncryptionResultFromMap(testEncDoc))
	if !errors.Is(err, ErrInvalidCryptoKey) {
		t.Fatalf("Decrypt should have failed with invalid crypto key, was: %v", err)
	}
}

func TestLegacyAesCryptoProvider_DecryptStoreMissingKid(t *testing.T) {
	keyStore := &InsecureKeyring{
		keys: map[string]Key{
			"myhmackey": {
				ID:    "myhmackey",
				Bytes: []byte("myauthpassword"),
			},
		},
	}

	provider := NewLegacyAes256CryptoProvider(keyStore, "mypublickey", "myhmackey")

	testEncDoc := map[string]interface{}{
		"alg":        "AES-256-HMAC-SHA256",
		"kid":        "mypublickey",
		"iv":         "Cfq84/46Qjet3EEQ1HUwSg==",
		"ciphertext": "sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==",
		"sig":        "rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM=",
	}

	_, err := provider.Decrypt(NewEncryptionResultFromMap(testEncDoc))
	if !errors.Is(err, ErrCryptoKeyNotFound) {
		t.Fatalf("Decrypt should have failed with missing crypto key, was: %v", err)
	}
}

func TestLegacyAesCryptoProvider_DecryptStoreMissingHmacKid(t *testing.T) {
	keyStore := &InsecureKeyring{
		keys: map[string]Key{
			"mypublickey": {
				ID:    "mypublickey",
				Bytes: []byte("!mysecretkey#9^5usdk39d&dlf)03sL"),
			},
		},
	}

	provider := NewLegacyAes256CryptoProvider(keyStore, "mypublickey", "myhmackey")

	testEncDoc := map[string]interface{}{
		"alg":        "AES-256-HMAC-SHA256",
		"kid":        "mypublickey",
		"iv":         "Cfq84/46Qjet3EEQ1HUwSg==",
		"ciphertext": "sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==",
		"sig":        "rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM=",
	}

	_, err := provider.Decrypt(NewEncryptionResultFromMap(testEncDoc))
	if !errors.Is(err, ErrCryptoKeyNotFound) {
		t.Fatalf("Decrypt should have failed with missing crypto key, was: %v", err)
	}
}

func TestLegacyAesCryptoProvider_DecryptMissingAlg(t *testing.T) {
	keyStore := &InsecureKeyring{
		keys: map[string]Key{
			"mypublickey": {
				ID:    "mypublickey",
				Bytes: []byte("!mysecretkey#9^5usdk39d&dlf)03sL"),
			},
			"myhmackey": {
				ID:    "myhmackey",
				Bytes: []byte("myauthpassword"),
			},
		},
	}

	provider := NewLegacyAes256CryptoProvider(keyStore, "mypublickey", "myhmackey")

	testEncDoc := map[string]interface{}{
		"kid":        "mypublickey",
		"iv":         "Cfq84/46Qjet3EEQ1HUwSg==",
		"ciphertext": "sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==",
		"sig":        "rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM=",
	}

	_, err := provider.Decrypt(NewEncryptionResultFromMap(testEncDoc))
	if err == nil {
		t.Fatalf("Decrypt should have failed")
	}
}

func TestLegacyAesCryptoProvider_DecryptNonMatchingAlg(t *testing.T) {
	keyStore := &InsecureKeyring{
		keys: map[string]Key{
			"mypublickey": {
				ID:    "mypublickey",
				Bytes: []byte("!mysecretkey#9^5usdk39d&dlf)03sL"),
			},
			"myhmackey": {
				ID:    "myhmackey",
				Bytes: []byte("myauthpassword"),
			},
		},
	}

	provider := NewLegacyAes256CryptoProvider(keyStore, "mypublickey", "myhmackey")

	testEncDoc := map[string]interface{}{
		"alg":        "AES-128-HMAC-SHA256",
		"kid":        "mypublickey",
		"iv":         "Cfq84/46Qjet3EEQ1HUwSg==",
		"ciphertext": "sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==",
		"sig":        "rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM=",
	}

	_, err := provider.Decrypt(NewEncryptionResultFromMap(testEncDoc))
	if err == nil {
		t.Fatalf("Decrypt should have failed")
	}
}

func TestLegacyAesCryptoProvider_DecryptMissingIV(t *testing.T) {
	keyStore := &InsecureKeyring{
		keys: map[string]Key{
			"mypublickey": {
				ID:    "mypublickey",
				Bytes: []byte("!mysecretkey#9^5usdk39d&dlf)03sL"),
			},
			"myhmackey": {
				ID:    "myhmackey",
				Bytes: []byte("myauthpassword"),
			},
		},
	}

	provider := NewLegacyAes256CryptoProvider(keyStore, "mypublickey", "myhmackey")

	testEncDoc := map[string]interface{}{
		"alg":        "AES-128-HMAC-SHA256",
		"kid":        "mypublickey",
		"ciphertext": "sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==",
		"sig":        "rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM=",
	}

	_, err := provider.Decrypt(NewEncryptionResultFromMap(testEncDoc))
	if err == nil {
		t.Fatalf("Decrypt should have failed")
	}
}

func TestLegacyAesCryptoProvider_DecryptMissingCiphertext(t *testing.T) {
	keyStore := &InsecureKeyring{
		keys: map[string]Key{
			"mypublickey": {
				ID:    "mypublickey",
				Bytes: []byte("!mysecretkey#9^5usdk39d&dlf)03sL"),
			},
			"myhmackey": {
				ID:    "myhmackey",
				Bytes: []byte("myauthpassword"),
			},
		},
	}

	provider := NewLegacyAes256CryptoProvider(keyStore, "mypublickey", "myhmackey")

	testEncDoc := map[string]interface{}{
		"alg": "AES-256-HMAC-SHA256",
		"kid": "mypublickey",
		"iv":  "Cfq84/46Qjet3EEQ1HUwSg==",
		"sig": "rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM=",
	}

	_, err := provider.Decrypt(NewEncryptionResultFromMap(testEncDoc))
	if err == nil {
		t.Fatalf("Decrypt should have failed")
	}
}

func TestLegacyAesCryptoProvider_DecryptMissingSig(t *testing.T) {
	keyStore := &InsecureKeyring{
		keys: map[string]Key{
			"mypublickey": {
				ID:    "mypublickey",
				Bytes: []byte("!mysecretkey#9^5usdk39d&dlf)03sL"),
			},
			"myhmackey": {
				ID:    "myhmackey",
				Bytes: []byte("myauthpassword"),
			},
		},
	}

	provider := NewLegacyAes256CryptoProvider(keyStore, "mypublickey", "myhmackey")

	testEncDoc := map[string]interface{}{
		"alg":        "AES-256-HMAC-SHA256",
		"kid":        "mypublickey",
		"iv":         "Cfq84/46Qjet3EEQ1HUwSg==",
		"ciphertext": "sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==",
	}

	_, err := provider.Decrypt(NewEncryptionResultFromMap(testEncDoc))
	if err == nil {
		t.Fatalf("Decrypt should have failed")
	}
}

func TestLegacyAesCryptoProvider_DecryptInvalidCiphertext(t *testing.T) {
	keyStore := &InsecureKeyring{
		keys: map[string]Key{
			"mypublickey": {
				ID:    "mypublickey",
				Bytes: []byte("!mysecretkey#9^5usdk39d&dlf)03sL"),
			},
			"myhmackey": {
				ID:    "myhmackey",
				Bytes: []byte("myauthpassword"),
			},
		},
	}

	provider := NewLegacyAes256CryptoProvider(keyStore, "mypublickey", "myhmackey")

	testEncDoc := map[string]interface{}{
		"alg":        "AES-256-HMAC-SHA256",
		"kid":        "mypublickey",
		"iv":         "Cfq84/46Qjet3EEQ1HUwSg==",
		"ciphertext": "sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89=",
		"sig":        "rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM=",
	}

	_, err := provider.Decrypt(NewEncryptionResultFromMap(testEncDoc))
	if !errors.Is(err, ErrInvalidCipherText) {
		t.Fatalf("Decrypt should have failed with invalid cipher text, was: %v", err)
	}
}
