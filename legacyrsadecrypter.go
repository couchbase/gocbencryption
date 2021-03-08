/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

package gocbfieldcrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"github.com/pkg/errors"
)

// LegacyRsaCryptoDecrypter provides a way to decrypt fields encrypted using RSA in a previous version of the
// library.
type LegacyRsaCryptoDecrypter struct {
	keyStore Keyring
	keyFn    LegacyKeyFn
}

// NewLegacyRsaCryptoDecrypter creates a new LegacyRsaCryptoDecrypter.
func NewLegacyRsaCryptoDecrypter(keyring Keyring, keyFn LegacyKeyFn) *LegacyRsaCryptoDecrypter {
	return &LegacyRsaCryptoDecrypter{
		keyStore: keyring,
		keyFn:    keyFn,
	}
}

// Algorithm returns the algorithm used by this provider.
func (cp *LegacyRsaCryptoDecrypter) Algorithm() string {
	return "RSA-2048-OEP"
}

// Decrypt decrypts the provided EncryptionResult.
func (cp *LegacyRsaCryptoDecrypter) Decrypt(result *EncryptionResult) ([]byte, error) {
	keyID, ok := result.GetKey()
	if !ok {
		return nil, wrapError(ErrCryptoKeyNotFound, "kid not found in result")
	}

	privateKeyID, err := cp.keyFn(keyID)
	if err != nil {
		return nil, wrapError(err, "failed to get key from key function")
	}
	privateKey, err := cp.keyStore.Get(privateKeyID)
	if err != nil {
		return nil, wrapError(err, "failed to get key from store")
	}

	cipherText, ok := result.Get("ciphertext")
	if !ok {
		return nil, errors.New("could not get ciphertext from data")
	}

	alg, err := result.Algorithm()
	if err != nil {
		return nil, err
	}

	encData, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}

	privKey, err := parsePKCS1PrivateKey(privateKey.Bytes)
	if err != nil {
		return nil, err
	}

	if alg != cp.Algorithm() {
		return nil, errors.New("encryption algorithm did not match configured algorithm")
	}

	decData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encData, nil)
	if err != nil {
		return nil, err
	}

	return decData, nil
}
