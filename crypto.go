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
	"strings"
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

func EncryptVal(val interface{}, crypt CryptoProvider) (map[string]interface{}, error) {

	byteConversion, err := json.Marshal(val)
	byteConversion = json.RawMessage(byteConversion)

	if err != nil {
		return nil, err
	}

	encData, err := crypt.Encrypt(byteConversion)

	if err != nil {
		return nil, err
	}

	var temp map[string]interface{}
	err = json.Unmarshal(encData, &temp)

	if err != nil {
		return nil, err
	}

	return temp, nil
}

func EncryptJsonFieldsRecursive(doc map[string]interface{}, fields map[string]CryptoProvider, depth int) error {

	for key, docPart := range doc {

		//Loop through the fields that need encryption which are represented as a dot notation path
		for field, crypt := range fields {

			//covert the dot notation to a slice
			path := strings.Split(field, ".")

			for ind, part := range path {
				//only check parts at the level we are at
				if ind == depth && part == key {

					v := reflect.ValueOf(docPart)

					//don't encrypt a part if we are not at the end of the path
					if (v.Kind() == reflect.Map || v.Kind() == reflect.Slice) && ind+1 < len(path) {
						//check the next level
						switch v.Kind() {
						case reflect.Slice:
							for _, slicePart := range docPart.([]interface{}) {
								EncryptJsonFieldsRecursive(slicePart.(map[string]interface{}), fields, ind+1)
							}
						case reflect.Map:
							EncryptJsonFieldsRecursive(docPart.(map[string]interface{}), fields, ind+1)
						}

					} else {

						result, err := EncryptVal(docPart, crypt)

						if err != nil {
							return err
						}

						//add the encrypted value to the doc
						doc["__crypt_"+part] = result

						//remove the original non-encrypted version
						delete(doc, part)
					}
				}
			}
		}
	}

	return nil
}

func EncryptJsonFields(data []byte, fields map[string]CryptoProvider) ([]byte, error) {
	var doc map[string]interface{}

	err := json.Unmarshal(data, &doc)
	if err != nil {
		return nil, err
	}

	err = EncryptJsonFieldsRecursive(doc, fields, 0)

	if err != nil {
		return nil, err
	}

	newBytes, err := json.Marshal(doc)

	if err != nil {
		return nil, err
	}

	return newBytes, nil
}

func DecryptVal(val interface{}, crypt CryptoProvider) (interface{}, error) {

	byteConversion, _ := json.Marshal(val)

	encData, err := crypt.Decrypt(byteConversion)

	var temp interface{}
	err = json.Unmarshal(encData, &temp)

	if err != nil {
		return nil, err
	}

	return temp, nil

}

func DecryptJsonFieldsRecursive(doc map[string]interface{}, fields map[string]CryptoProvider, depth int) error {

	for key, docPart := range doc {

		//Loop through the fields that need encryption which are represented as a dot notation path
		for field, crypt := range fields {

			//covert the dot notation to a slice
			path := strings.Split(field, ".")

			for ind, part := range path {
				//only check parts at the level we are at matching on encrypted or non-encrypted keys
				if ind == depth && ("__crypt_"+part == key || part == key) {
					v := reflect.ValueOf(docPart)

					//don't decrypt a part if we are not at the end of the path
					if (v.Kind() == reflect.Map || v.Kind() == reflect.Slice) && ind+1 < len(path) {
						//check the next level
						switch v.Kind() {
						case reflect.Slice:
							for _, slicePart := range docPart.([]interface{}) {
								DecryptJsonFieldsRecursive(slicePart.(map[string]interface{}), fields, ind+1)
							}
						case reflect.Map:
							DecryptJsonFieldsRecursive(docPart.(map[string]interface{}), fields, ind+1)
						}

					} else {

						//Only decrypt encrypted values which we know have been encrypted because they have "__crypt_" in the path
						if "__crypt_"+part == key {
							result, err := DecryptVal(docPart, crypt)

							if err != nil {
								return err
							}

							//add the decrypted value to the doc
							doc[part] = result

							//remove the encrypted doc part
							delete(doc, "__crypt_"+part)
						}

					}
				}
			}
		}
	}

	return nil
}

func DecryptJsonFields(bytes []byte, fields map[string]CryptoProvider) ([]byte, error) {
	var doc map[string]interface{}

	err := json.Unmarshal(bytes, &doc)
	if err != nil {
		return nil, err
	}

	err = DecryptJsonFieldsRecursive(doc, fields, 0)

	if err != nil {
		return nil, err
	}

	newBytes, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}

	return newBytes, nil
}
