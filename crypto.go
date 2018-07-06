/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

package gocbfieldcrypt

import (
	"encoding/json"
	"errors"
	"fmt"
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
	KeyId     string
}

func providerFromField(f field, providers map[string]CryptoProvider) (CryptoProvider, error) {
	provider, ok := providers[f.algorithm]
	if ok {
		return provider, nil
	}

	return nil, newCryptoError(
		CryptoProviderNotFound,
		fmt.Sprintf("the cryptographic provider could not be found for the alias: %s", f.algorithm),
	)
}

func EncryptJsonStruct(bytes []byte, t reflect.Type, providers map[string]CryptoProvider) ([]byte, error) {
	fieldProviders, err := typeProviders(t, providers)
	if err != nil {
		return nil, err
	}

	return EncryptJsonFields(bytes, fieldProviders)
}

func DecryptJsonStruct(bytes []byte, t reflect.Type, providers map[string]CryptoProvider) ([]byte, error) {
	fieldProviders, err := typeProviders(t, providers)
	if err != nil {
		return nil, err
	}

	return DecryptJsonFields(bytes, fieldProviders)
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
				return nil, err
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
