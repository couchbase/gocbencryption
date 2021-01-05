/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

package gocbfieldcrypt

import (
	"encoding/base64"
	"errors"
)

// EncryptionResult is the encrypted form of a message.
type EncryptionResult struct {
	m map[string]interface{}
}

// AsMap converts the EncryptionResult to a map.
func (er *EncryptionResult) AsMap() map[string]interface{} {
	return er.m
}

// Put adds a key, value pair to the EncryptionResult.
func (er *EncryptionResult) Put(key string, val interface{}) {
	er.m[key] = val
}

// PutAndBase64Encode add a key, value pair to the EncryptionResult and base 64 encodes the value.
func (er *EncryptionResult) PutAndBase64Encode(key string, val []byte) {
	er.m[key] = base64.StdEncoding.EncodeToString(val)
}

// Get returns the corresponding value for a given key from the EncryptionResult.
func (er *EncryptionResult) Get(key string) (string, bool) {
	v, ok := er.m[key]
	if !ok {
		return "", false
	}
	str, ok := v.(string)
	if !ok {
		return "", false
	}

	return str, ok
}

// Get returns the key id from the EncryptionResult.
func (er *EncryptionResult) GetKey() (string, bool) {
	return er.Get("kid")
}

// GetFromBase64Encoded returns the corresponding value for a given key from the EncryptionResult, base 64 decoding
// the value first.
func (er *EncryptionResult) GetFromBase64Encoded(key string) ([]byte, error) {
	str, ok := er.Get(key)
	if !ok {
		return nil, ErrCryptoKeyNotFound
	}

	return base64.StdEncoding.DecodeString(str)
}

// Algorithm returns the algorithm that was used to create this EncryptionResult.
func (er *EncryptionResult) Algorithm() (string, error) {
	val, ok := er.m["alg"]
	if !ok {
		return "", errors.New("alg field missing in data")
	}

	v, ok := val.(string)
	if !ok {
		return "", errors.New("alg field could not be used as string")
	}

	return v, nil
}

// NewEncryptionResultFromAlgo creates a new EncryptionResult with the alg field populated.
func NewEncryptionResultFromAlgo(algo string) *EncryptionResult {
	m := map[string]interface{}{
		"alg": algo,
	}
	return &EncryptionResult{
		m: m,
	}
}

// NewEncryptionResultFromMap creates a new EncryptionResult from a map.
func NewEncryptionResultFromMap(m map[string]interface{}) *EncryptionResult {
	return &EncryptionResult{
		m: m,
	}
}
