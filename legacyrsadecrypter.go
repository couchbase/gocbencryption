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

type LegacyRsaCryptoProvider struct {
	keyStore     Keyring
	publicKeyID  string
	privateKeyID string
}

func NewLegacyRsaCryptoProvider(keyring Keyring, publicKeyAlias, privateKeyAlias string) *LegacyRsaCryptoProvider {
	return &LegacyRsaCryptoProvider{
		keyStore:     keyring,
		publicKeyID:  publicKeyAlias,
		privateKeyID: privateKeyAlias,
	}
}

func (cp *LegacyRsaCryptoProvider) Algorithm() string {
	return "RSA-2048-OEP"
}

// encrypt is used only for testing.
func (cp *LegacyRsaCryptoProvider) encrypt(data []byte) (*EncryptionResult, error) {
	pubKeyBytes, err := cp.keyStore.Get(cp.publicKeyID)
	if err != nil {
		return nil, err
	}

	pubKey, err := parsePKCS1PublicKey(pubKeyBytes.Bytes)
	if err != nil {
		return nil, err
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, data, nil)
	if err != nil {
		return nil, err
	}

	encBlock := map[string]interface{}{
		"kid":        cp.publicKeyID,
		"alg":        "RSA-2048-OEP",
		"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
	}

	return NewEncryptionResultFromMap(encBlock), nil
}

func (cp *LegacyRsaCryptoProvider) Decrypt(result *EncryptionResult) ([]byte, error) {
	if cp.publicKeyID == "" {
		return nil, errors.New("cryptographic providers require a non-nil, empty public and key identifier (kid) be configured")
	}
	if cp.privateKeyID == "" {
		return nil, errors.New("asymmetric key cryptographic providers require a non-nil, empty signing key be configured")
	}

	keyID, ok := result.GetKey()
	if !ok {
		return nil, wrapError(ErrCryptoKeyNotFound, "kid not found in result")
	}

	privateKey, err := cp.keyStore.Get(cp.privateKeyID)
	if err != nil {
		return nil, wrapError(err, "failed to get key from store")
	}

	if keyID != cp.publicKeyID {
		return nil, wrapError(ErrInvalidCryptoKey, "encryption key did not match configured key")
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
