/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

package gocbfieldcrypt

import (
	"reflect"

	"gopkg.in/couchbase/gocb.v1"
)

type Transcoder struct {
	BaseTranscoder gocb.Transcoder
	providers      map[string]CryptoProvider
}

// NewTranscoder creates a new initialized Transcoder.
func NewTranscoder() *Transcoder {
	return &Transcoder{
		providers: make(map[string]CryptoProvider),
	}
}

// Register registers a CryptoProvider with the transcoder.
func (t *Transcoder) Register(name string, provider CryptoProvider) {
	if t.providers == nil {
		t.providers = make(map[string]CryptoProvider)
	}
	t.providers[name] = provider
}

// Decodes retrieved bytes into a Go type.
func (t *Transcoder) Decode(data []byte, flags uint32, valuePtr interface{}) error {
	if t.providers == nil {
		t.providers = make(map[string]CryptoProvider)
	}
	transcoder := t.BaseTranscoder
	if transcoder == nil {
		transcoder = gocb.DefaultTranscoder{}
	}

	valueType := reflect.TypeOf(valuePtr)
	for valueType.Kind() == reflect.Ptr {
		valueType = valueType.Elem()
	}
	if valueType.Kind() != reflect.Struct {
		return transcoder.Decode(data, flags, valuePtr)
	}

	decData, err := DecryptJsonStruct(data, valueType, t.providers)
	if err != nil {
		return err
	}

	return transcoder.Decode(decData, flags, valuePtr)
}

// Encodes a Go type into bytes for storage.
func (t *Transcoder) Encode(value interface{}) ([]byte, uint32, error) {
	if t.providers == nil {
		t.providers = make(map[string]CryptoProvider)
	}
	transcoder := t.BaseTranscoder
	if transcoder == nil {
		transcoder = gocb.DefaultTranscoder{}
	}

	data, flags, err := transcoder.Encode(value)
	if err != nil {
		return nil, 0, err
	}

	valueType := reflect.TypeOf(value)
	for valueType.Kind() == reflect.Ptr {
		valueType = valueType.Elem()
	}
	if valueType.Kind() != reflect.Struct {
		return data, flags, err
	}

	encData, err := EncryptJsonStruct(data, valueType, t.providers)
	if err != nil {
		return nil, 0, err
	}

	return encData, flags, nil
}
