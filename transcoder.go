package gocbfieldcrypt

import (
	"gopkg.in/couchbase/gocb.v1"
	"reflect"
)

type Transcoder struct {
	BaseTranscoder gocb.Transcoder
	KeyStore KeyProvider
}

// Decodes retrieved bytes into a Go type.
func (t *Transcoder) Decode(data []byte, flags uint32, valuePtr interface{}) error {
	transcoder := t.BaseTranscoder
	if transcoder == nil {
		transcoder = gocb.DefaultTranscoder{}
	}

	decData, err := DecryptJsonStruct(data, reflect.TypeOf(valuePtr), t.KeyStore)
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

	encData, err := EncryptJsonStruct(data, reflect.TypeOf(value), t.KeyStore)
	if err != nil {
		return nil, 0, err
	}

	return encData, flags, nil
}