/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

package gocbfieldcrypt

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/pkg/errors"
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
	KeyId     string
}

func providerFromField(f field, keys KeyProvider) (CryptoProvider, error) {
	switch f.algorithm {
	case "aes256":
		fallthrough
	case "AES-256-HMAC-SHA256":
		if len(f.options) == 0 {
			return nil, newCryptoError(
				CryptoProviderMissingPublicKey,
				fmt.Sprintf("cryptographic providers require a non-nil, empty public and key identifier (kid) be configured for the alias: %s", f.algorithm),
			)
		} else if len(f.options) == 1 {
			return nil, newCryptoError(
				CryptoProviderMissingPrivateKey,
				fmt.Sprintf("symmetric key cryptographic providers require a non-nil, empty private key be configured for the alias: %s", f.algorithm),
			)
		}

		return &AesCryptoProvider{
			Alias:    f.algorithm,
			KeyStore: keys,
			Key:      f.options[0],
			HmacKey:  f.options[1],
		}, nil
	case "rsa2048":
		fallthrough
	case "RSA-2048-OEP":
		if len(f.options) == 0 {
			return nil, newCryptoError(
				CryptoProviderMissingPublicKey,
				fmt.Sprintf("cryptographic providers require a non-nil, empty public and key identifier (kid) be configured for the alias: %s", f.algorithm),
			)
		} else if len(f.options) == 1 {
			return nil, newCryptoError(
				CryptoProviderMissingSigningKey,
				fmt.Sprintf("asymmetric key cryptographic providers require a non-nil, empty signing key be configured for the alias: %s", f.algorithm),
			)
		}

		return &RsaCryptoProvider{
			KeyStore:   keys,
			PublicKey:  f.options[0],
			PrivateKey: f.options[1],
		}, nil
	}

	return nil, newCryptoError(
		CryptoProviderNotFound,
		fmt.Sprintf("the cryptographic provider could not be found for the alias: %s", f.algorithm),
	)
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
				return nil, errors.Wrap(err, "the encryption of the field failed")
			}

			doc["__crypt_"+field] = encData
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
		if val, ok := doc["__crypt_"+field]; ok {
			encData, err := crypt.Decrypt(val)
			if err != nil {
				return nil, errors.Wrap(err, "the decryption of the field failed")
			}

			doc[field] = encData
			delete(doc, "__crypt_"+field)
		}
	}

	newBytes, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}

	return newBytes, nil
}
