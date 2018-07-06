/*
 * Copyright (c) 2018 Couchbase, Inc.
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
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
)

type RsaCryptoProvider struct {
	Alias      string
	KeyStore   KeyProvider
	PublicKey  string
	PrivateKey string
}

func (cp *RsaCryptoProvider) Encrypt(data []byte) ([]byte, error) {
	if cp.PublicKey == "" {
		return nil, newCryptoError(
			CryptoProviderMissingPublicKey,
			fmt.Sprintf("cryptographic providers require a non-nil, empty public and key identifier (kid) be configured for the alias: %s", cp.Alias),
		)
	}
	if cp.PrivateKey == "" {
		return nil, newCryptoError(
			CryptoProviderMissingSigningKey,
			fmt.Sprintf("asymmetric key cryptographic providers require a non-nil, empty signing key be configured for the alias: %s", cp.Alias),
		)
	}

	pubKeyBytes, err := cp.KeyStore.GetKey(cp.PublicKey)
	if err != nil {
		return nil, err
	}

	pubKey, err := parsePKCS1PublicKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, data, nil)
	if err != nil {
		return nil, err
	}

	encBlock := cipherData{
		KeyId:      cp.PublicKey,
		Algorithm:  "RSA-2048-OEP",
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}

	dataBlock, err := json.Marshal(encBlock)
	if err != nil {
		return nil, err
	}

	return dataBlock, nil
}

func (cp *RsaCryptoProvider) Decrypt(data []byte) ([]byte, error) {
	if cp.PublicKey == "" {
		return nil, newCryptoError(
			CryptoProviderMissingPublicKey,
			fmt.Sprintf("cryptographic providers require a non-nil, empty public and key identifier (kid) be configured for the alias: %s", cp.Alias),
		)
	}
	if cp.PrivateKey == "" {
		return nil, newCryptoError(
			CryptoProviderMissingSigningKey,
			fmt.Sprintf("asymmetric key cryptographic providers require a non-nil, empty signing key be configured for the alias: %s", cp.Alias),
		)
	}

	var encBlock cipherData
	err := json.Unmarshal(data, &encBlock)
	if err != nil {
		return nil, err
	}

	if encBlock.KeyId != cp.PublicKey {
		return nil, errors.New("encryption key did not match configured key")
	}

	encData, err := base64.StdEncoding.DecodeString(encBlock.Ciphertext)
	if err != nil {
		return nil, err
	}

	privKeyBytes, err := cp.KeyStore.GetKey(cp.PrivateKey)
	if err != nil {
		return nil, err
	}

	privKey, err := parsePKCS1PrivateKey(privKeyBytes)
	if err != nil {
		return nil, err
	}

	if encBlock.Algorithm != "RSA-2048-OEP" {
		return nil, errors.New("encryption algorithm did not match configured algorithm")
	}

	decData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encData, nil)
	if err != nil {
		return nil, err
	}

	return decData, nil
}
