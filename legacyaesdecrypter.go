/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

package gocbfieldcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// LegacyAes128CryptoDecrypter provides a way to decrypt fields encrypted using AES 128 in a previous version of the
// library.
type LegacyAes128CryptoDecrypter struct {
	provider legacyAesCryptoProvider
}

// LegacyAes256CryptoDecrypter provides a way to decrypt fields encrypted using AES 256 in a previous version of the
// library.
type LegacyAes256CryptoDecrypter struct {
	provider legacyAesCryptoProvider
}

type legacyAesCryptoProvider struct {
	keyStore  Keyring
	keyID     string
	hmacKeyID string
}

// NewLegacyAes128CryptoDecrypter creates a new LegacyAes128CryptoDecrypter.
func NewLegacyAes128CryptoDecrypter(keyring Keyring, keyID, hmacKeyAlias string) *LegacyAes128CryptoDecrypter {
	return &LegacyAes128CryptoDecrypter{
		provider: legacyAesCryptoProvider{
			keyStore:  keyring,
			keyID:     keyID,
			hmacKeyID: hmacKeyAlias,
		},
	}
}

// NewLegacyAes256CryptoDecrypter creates a new LegacyAes256CryptoDecrypter.
func NewLegacyAes256CryptoDecrypter(keyring Keyring, keyID, hmacKeyAlias string) *LegacyAes256CryptoDecrypter {
	return &LegacyAes256CryptoDecrypter{
		provider: legacyAesCryptoProvider{
			keyStore:  keyring,
			keyID:     keyID,
			hmacKeyID: hmacKeyAlias,
		},
	}
}

// Algorithm returns the algorithm used by this provider.
func (cp *LegacyAes128CryptoDecrypter) Algorithm() string {
	return "AES-128-HMAC-SHA256"
}

// Decrypt decrypts the provided EncryptionResult.
func (cp *LegacyAes128CryptoDecrypter) Decrypt(result *EncryptionResult) ([]byte, error) {
	return cp.provider.decrypt(result, cp.Algorithm())
}

// Algorithm returns the algorithm used by this provider.
func (cp *LegacyAes256CryptoDecrypter) Algorithm() string {
	return "AES-256-HMAC-SHA256"
}

// Decrypt decrypts the provided EncryptionResult.
func (cp *LegacyAes256CryptoDecrypter) Decrypt(result *EncryptionResult) ([]byte, error) {
	return cp.provider.decrypt(result, cp.Algorithm())
}

func (cp *legacyAesCryptoProvider) decrypt(result *EncryptionResult, algo string) ([]byte, error) {
	keyID, ok := result.GetKey()
	if !ok {
		return nil, wrapError(ErrInvalidCryptoKey, "kid not found in result")
	}

	if keyID != cp.keyID {
		return nil, wrapError(ErrInvalidCryptoKey, "encryption key did not match configured key")
	}

	key, err := cp.keyStore.Get(keyID)
	if err != nil {
		return nil, wrapError(err, "failed to get key from store")
	}

	hmacKey := key
	if cp.hmacKeyID != "" {
		hmacKey, err = cp.keyStore.Get(cp.hmacKeyID)
		if err != nil {
			return nil, wrapError(err, "failed to get key from store")
		}
	}

	alg, err := result.Algorithm()
	if err != nil {
		return nil, err
	}

	if alg != algo {
		return nil, errors.New("encryption algorithm did not match configured algorithm")
	}

	iv, ok := result.Get("iv")
	if !ok {
		return nil, errors.New("could not get iv from data")
	}

	cipherText, ok := result.Get("ciphertext")
	if !ok {
		return nil, errors.New("could not get ciphertext from data")
	}

	signature, ok := result.Get("sig")
	if !ok {
		return nil, errors.New("could not get sig from data")
	}

	var sigBytes []byte
	sigBytes = append(sigBytes, key.ID...)
	sigBytes = append(sigBytes, alg...)
	sigBytes = append(sigBytes, iv...)
	sigBytes = append(sigBytes, cipherText...)

	mac := hmac.New(sha256.New, hmacKey.Bytes)
	_, err = mac.Write(sigBytes)
	if err != nil {
		return nil, err
	}
	sig := mac.Sum(nil)

	srcSig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, err
	}

	if !hmac.Equal(sig, srcSig) {
		return nil, ErrInvalidCipherText
	}

	encData, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}

	srcIv, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key.Bytes)
	if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCDecrypter(block, srcIv)

	decData := make([]byte, len(encData))
	cbc.CryptBlocks(decData, encData)

	decData = pkcs5Trimming(decData)

	return decData, nil
}
