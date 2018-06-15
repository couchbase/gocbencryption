/*
 * Copyright (c) 2018 Couchbase, Inc.
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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
)

type AesCryptoProvider struct {
	Alias    string
	KeyStore KeyProvider
	Key      string
	HmacKey  string
}

func (cp *AesCryptoProvider) getAlgNameFromKey(key, hmacKey []byte) (string, error) {
	switch len(key) {
	case 16:
		return "AES-128-HMAC-SHA256", nil
	case 32:
		return "AES-256-HMAC-SHA256", nil
	default:
		return "", newCryptoError(
			CryptoProviderKeySize,
			fmt.Sprintf("the key found does not match the size of the key that the algorithm expects for the alias:"+
				" %s. Expected key size was %d and configured key is %d", cp.Alias, 32, len(key)))
	}
}

func (cp *AesCryptoProvider) Encrypt(data []byte) ([]byte, error) {
	key, err := cp.KeyStore.GetKey(cp.Key)
	if err != nil {
		return nil, err
	}

	hmacKey := key
	if cp.HmacKey != "" {
		hmacKey, err = cp.KeyStore.GetKey(cp.HmacKey)
		if err != nil {
			return nil, err
		}
	}

	algName, err := cp.getAlgNameFromKey(key, hmacKey)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, 16)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCEncrypter(block, iv)

	data = pkcs5Padding(data, block.BlockSize())

	encData := make([]byte, len(data))
	cbc.CryptBlocks(encData, data)

	codedIv := base64.StdEncoding.EncodeToString(iv)
	codedCiphertext := base64.StdEncoding.EncodeToString(encData)

	var sigBytes []byte
	sigBytes = append(sigBytes, cp.Key...)
	sigBytes = append(sigBytes, algName...)
	sigBytes = append(sigBytes, codedIv...)
	sigBytes = append(sigBytes, codedCiphertext...)

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(sigBytes)
	sig := mac.Sum(nil)

	codedSig := base64.StdEncoding.EncodeToString(sig)

	encBlock := cipherData{
		Algorithm:  algName,
		KeyId:      cp.Key,
		Iv:         codedIv,
		Ciphertext: codedCiphertext,
		Signature:  codedSig,
	}

	dataBlock, err := json.Marshal(encBlock)
	if err != nil {
		return nil, err
	}

	return dataBlock, nil
}

func (cp *AesCryptoProvider) Decrypt(data []byte) ([]byte, error) {
	key, err := cp.KeyStore.GetKey(cp.Key)
	if err != nil {
		return nil, err
	}

	hmacKey := key
	if cp.HmacKey != "" {
		hmacKey, err = cp.KeyStore.GetKey(cp.HmacKey)
		if err != nil {
			return nil, err
		}
	}

	algName, err := cp.getAlgNameFromKey(key, hmacKey)
	if err != nil {
		return nil, err
	}

	var encBlock cipherData
	err = json.Unmarshal(data, &encBlock)
	if err != nil {
		return nil, err
	}

	if encBlock.KeyId != cp.Key {
		return nil, errors.New("encryption key did not match configured key")
	}

	if encBlock.Algorithm != algName {
		return nil, errors.New("encryption algorithm did not match configured algorithm")
	}

	var sigBytes []byte
	sigBytes = append(sigBytes, encBlock.KeyId...)
	sigBytes = append(sigBytes, encBlock.Algorithm...)
	sigBytes = append(sigBytes, encBlock.Iv...)
	sigBytes = append(sigBytes, encBlock.Ciphertext...)

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(sigBytes)
	sig := mac.Sum(nil)

	srcSig, err := base64.StdEncoding.DecodeString(encBlock.Signature)
	if err != nil {
		return nil, err
	}

	if !hmac.Equal(sig, srcSig) {
		return nil, newCryptoError(
			CryptoProviderSigningFailed,
			fmt.Sprintf("The authentication failed while checking the signature of the message payload for the alias: %s", cp.Alias),
		)
	}

	encData, err := base64.StdEncoding.DecodeString(encBlock.Ciphertext)
	if err != nil {
		return nil, err
	}

	srcIv, err := base64.StdEncoding.DecodeString(encBlock.Iv)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCDecrypter(block, srcIv)

	decData := make([]byte, len(encData))
	cbc.CryptBlocks(decData, encData)

	decData = pkcs5Trimming(decData)

	return decData, nil
}
