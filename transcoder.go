package gocbfieldcrypt

import (
	"gopkg.in/couchbase/gocb.v1"
	"reflect"
)

type Transcoder struct {
	BaseTranscoder gocb.Transcoder
	KeyStore       KeyProvider
}

// Decodes retrieved bytes into a Go type.
func (t *Transcoder) Decode(data []byte, flags uint32, valuePtr interface{}) error {
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

	decData, err := DecryptJsonStruct(data, valueType, t.KeyStore)
	if err != nil {
		return err
	}

	return transcoder.Decode(decData, flags, valuePtr)
}

// Encodes a Go type into bytes for storage.
func (t *Transcoder) Encode(value interface{}) ([]byte, uint32, error) {
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

	encData, err := EncryptJsonStruct(data, valueType, t.KeyStore)
	if err != nil {
		return nil, 0, err
	}

	return encData, flags, nil
}
