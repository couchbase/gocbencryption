package gocbfieldcrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
)

type RsaCryptoProvider struct {
	KeyStore   KeyProvider
	PublicKey  string
	PrivateKey string
}

func (cp *RsaCryptoProvider) Encrypt(data []byte) ([]byte, error) {
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
