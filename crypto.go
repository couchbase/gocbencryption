package gocbfieldcrypt

import (
	"encoding/json"
	"errors"
	"reflect"
)

type KeyProvider interface {
	GetKey(name string) ([]byte, error)
}

type InsecureKeystore struct {
	Keys map[string][]byte
}

func (ks *InsecureKeystore) GetKey(name string) ([]byte, error) {
	if key, ok := ks.Keys[name]; ok {
		return key, nil
	}
	return nil, errors.New("invalid key")
}

type CryptoProvider interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
}

type cipherData struct {
	Algorithm  string `json:"alg,omitempty"`
	KeyId      string `json:"kid,omitempty"`
	Iv         string `json:"iv,omitempty"`
	Ciphertext string `json:"ciphertext,omitempty"`
	Signature  string `json:"sig,omitempty"`
}

type FieldDefinition struct {
	Algorithm string
	KeyId string
}

func providerFromField(f field, keys KeyProvider) (CryptoProvider, error) {
	switch f.algorithm {
	case "aes256":
		fallthrough
	case "AES-256-HMAC-SHA256":
		if len(f.options) < 2 {
			return nil, errors.New("invalid crypto options")
		}

		return &AesCryptoProvider{
			KeyStore: keys,
			Key: f.options[0],
			HmacKey: f.options[1],
		}, nil
	case "rsa2048":
		fallthrough
	case "RSA-2048-OEP":
		if len(f.options) < 2 {
			return nil, errors.New("invalid crypto options")
		}

		return &RsaCryptoProvider{
			KeyStore: keys,
			PublicKey: f.options[0],
			PrivateKey: f.options[1],
		}, nil
	}

	return nil, errors.New("invalid algorithm specified")
}

func EncryptJsonStruct(bytes []byte, t reflect.Type, keys KeyProvider) ([]byte, error) {
	providers, err := typeProviders(t, keys)
	if err != nil {
		return nil, err
	}

	return EncryptJsonFields(bytes, providers)
}

func DecryptJsonStruct(bytes []byte, t reflect.Type, keys KeyProvider) ([]byte, error) {
	providers, err := typeProviders(t, keys)
	if err != nil {
		return nil, err
	}

	return DecryptJsonFields(bytes, providers)
}

func EncryptJsonFields(bytes []byte, fields map[string]CryptoProvider) ([]byte, error) {
	var doc map[string]json.RawMessage

	err := json.Unmarshal(bytes, &doc)
	if err != nil {
		return nil, err
	}

	for field, crypt := range fields {
		if val, ok := doc[field]; ok {
			encData, err := crypt.Encrypt(val)
			if err != nil {
				return nil, err
			}

			doc["__crypt_" + field] = encData
			delete(doc, field)
		}
	}

	newBytes, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}

	return newBytes, nil
}

func DecryptJsonFields(bytes []byte, fields map[string]CryptoProvider) ([]byte, error) {
	var doc map[string]json.RawMessage

	err := json.Unmarshal(bytes, &doc)
	if err != nil {
		return nil, err
	}

	for field, crypt := range fields {
		if val, ok := doc["__crypt_" + field]; ok {
			encData, err := crypt.Decrypt(val)
			if err != nil {
				return nil, err
			}

			doc[field] = encData
			delete(doc, "__crypt_" + field)
		}
	}

	newBytes, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}

	return newBytes, nil
}
