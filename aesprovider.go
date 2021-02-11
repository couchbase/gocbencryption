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
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
)

// AeadAes256CbcHmacSha512Provider provides a way to create encrypters and decrypters for the AEAD_AES_256_CBC_HMAC_SHA512
// algorithm.
type AeadAes256CbcHmacSha512Provider struct {
	keyStore Keyring
}

// AeadAes256CbcHmacSha512ProviderEncrypter provides a way to perform encryption for the AEAD_AES_256_CBC_HMAC_SHA512 algorithm.
type AeadAes256CbcHmacSha512ProviderEncrypter struct {
	provider *AeadAes256CbcHmacSha512Provider
	keyID    string
	iv       []byte
}

// AeadAes256CbcHmacSha512ProviderDecrypter provides a way to perform decryption for the AEAD_AES_256_CBC_HMAC_SHA512 algorithm.
type AeadAes256CbcHmacSha512ProviderDecrypter struct {
	provider *AeadAes256CbcHmacSha512Provider
}

// NewAeadAes256CbcHmacSha512Provider creates a new AeadAes256CbcHmacSha512Provider.
func NewAeadAes256CbcHmacSha512Provider(keyring Keyring) *AeadAes256CbcHmacSha512Provider {
	return &AeadAes256CbcHmacSha512Provider{
		keyStore: keyring,
	}
}

func (p *AeadAes256CbcHmacSha512Provider) algorithm() string {
	return "AEAD_AES_256_CBC_HMAC_SHA512"
}

// EncrypterForKey returns a AeadAes256CbcHmacSha512ProviderEncrypter which will use the provided key.
func (p *AeadAes256CbcHmacSha512Provider) EncrypterForKey(keyID string) *AeadAes256CbcHmacSha512ProviderEncrypter {
	return &AeadAes256CbcHmacSha512ProviderEncrypter{
		provider: p,
		keyID:    keyID,
		iv:       nil,
	}
}

// Decrypter returns a AeadAes256CbcHmacSha512ProviderDecrypter.
func (p *AeadAes256CbcHmacSha512Provider) Decrypter() *AeadAes256CbcHmacSha512ProviderDecrypter {
	return &AeadAes256CbcHmacSha512ProviderDecrypter{
		provider: p,
	}
}

// Encrypt encrypts a plaintext into a EncryptionResult.
func (p *AeadAes256CbcHmacSha512ProviderEncrypter) Encrypt(plaintext []byte) (*EncryptionResult, error) {
	key, err := p.provider.keyStore.Get(p.keyID)
	if err != nil {
		return nil, wrapError(err, "failed to get key from store")
	}

	b, err := p.encrypt(key.Bytes, plaintext, nil)
	if err != nil {
		return nil, err
	}

	e := NewEncryptionResultFromAlgo(p.provider.algorithm())
	e.Put("kid", key.ID)
	e.PutAndBase64Encode("ciphertext", b)

	return e, nil
}

func (p *AeadAes256CbcHmacSha512ProviderEncrypter) encrypt(key, plaintext, associatedData []byte) ([]byte, error) {
	err := p.provider.verifyKeyLength(key)
	if err != nil {
		return nil, wrapError(err, "invalid key length")
	}

	aesKey := key[32:]
	hmacKey := key[:32]

	iv := p.iv
	if len(iv) == 0 {
		iv = make([]byte, 16)
		_, err := rand.Read(iv)
		if err != nil {
			return nil, err
		}
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCEncrypter(block, iv)

	// pkcs5 is identical to pkcs7 in this usage.
	plaintext = pkcs5Padding(plaintext, block.BlockSize())

	encData := make([]byte, len(plaintext))
	cbc.CryptBlocks(encData, plaintext)

	aesCipher := append(iv, encData...)

	associatedLenData := make([]byte, 8)
	binary.BigEndian.PutUint64(associatedLenData, uint64(len(associatedData)*8))

	mac := hmac.New(sha512.New, hmacKey)
	_, err = mac.Write(associatedData)
	if err != nil {
		return nil, err
	}
	_, err = mac.Write(aesCipher)
	if err != nil {
		return nil, err
	}
	_, err = mac.Write(associatedLenData)
	if err != nil {
		return nil, err
	}
	sig := mac.Sum(nil)
	sig = sig[:32]

	return append(aesCipher, sig...), nil
}

// Algorithm returns the algorithm used by this decrypter.
func (p *AeadAes256CbcHmacSha512ProviderDecrypter) Algorithm() string {
	return p.provider.algorithm()
}

// Decrypt decrypts the provided EncryptionResult.
func (p *AeadAes256CbcHmacSha512ProviderDecrypter) Decrypt(result *EncryptionResult) ([]byte, error) {
	kid, ok := result.GetKey()
	if !ok {
		return nil, wrapError(ErrInvalidCryptoKey, "failed to get kid from result")
	}

	key, err := p.provider.keyStore.Get(kid)
	if err != nil {
		return nil, wrapError(err, "failed to get key from store")
	}

	cipherText, err := result.GetFromBase64Encoded("ciphertext")
	if err != nil {
		return nil, wrapError(ErrInvalidCipherText, "could not get ciphertext from result")
	}

	b, err := p.decrypt(key.Bytes, cipherText, nil)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (p *AeadAes256CbcHmacSha512ProviderDecrypter) decrypt(key, ciphertext, associatedData []byte) ([]byte, error) {
	err := p.provider.verifyKeyLength(key)
	if err != nil {
		return nil, wrapError(err, "invalid key length")
	}

	aesKey := key[32:]
	hmacKey := key[:32]

	aesCipher := ciphertext[:len(ciphertext)-32]
	authTag := ciphertext[len(ciphertext)-32:]

	associatedLenData := make([]byte, 8)
	binary.BigEndian.PutUint64(associatedLenData, uint64(len(associatedData)*8))

	mac := hmac.New(sha512.New, hmacKey)
	_, err = mac.Write(associatedData)
	if err != nil {
		return nil, err
	}
	_, err = mac.Write(aesCipher)
	if err != nil {
		return nil, err
	}
	_, err = mac.Write(associatedLenData)
	if err != nil {
		return nil, err
	}
	sig := mac.Sum(nil)
	sig = sig[:32]

	if !hmac.Equal(authTag, sig) {
		return nil, ErrInvalidCipherText
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	iv := aesCipher[:16]
	data := aesCipher[16:]

	cbc := cipher.NewCBCDecrypter(block, iv)

	decData := make([]byte, len(data))
	cbc.CryptBlocks(decData, data)

	decData = pkcs5Trimming(decData)

	return decData, nil
}

func (p *AeadAes256CbcHmacSha512Provider) verifyKeyLength(key []byte) error {
	if len(key) != 64 {
		return ErrInvalidCryptoKey
	}

	return nil
}
