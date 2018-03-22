package gocbfieldcrypt

import (
	"encoding/json"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

type AesCryptoProvider struct {
	KeyStore KeyProvider
	Key string
	HmacKey string
}

func (cp *AesCryptoProvider) getAlgNameFromKey(key, hmacKey []byte) (string, error) {
	switch len(key) {
	case 32:
		return "AES-256-HMAC-SHA256", nil
	default:
		return "", fmt.Errorf("invalid cipher key size (must be 32 bytes, was %d).", len(key))
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
		return nil, errors.New("encryption algorithm did not match configured algorithm.")
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
		return nil, errors.New("encrypted data was tampered")
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
