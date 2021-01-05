/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

package gocbfieldcrypt

import (
	"encoding/json"
	"errors"
	"github.com/couchbase/gocb/v2"
	"reflect"
	"strconv"
)

type Transcoder struct {
	baseTranscoder gocb.Transcoder
	mgr            CryptoManager
}

// NewTranscoder creates a new initialized Transcoder.
func NewTranscoder(baseTranscoder gocb.Transcoder, mgr CryptoManager) *Transcoder {
	return &Transcoder{
		baseTranscoder: baseTranscoder,
		mgr:            mgr,
	}
}

// // Decodes retrieved bytes into a Go type.
func (t *Transcoder) Decode(data []byte, flags uint32, valuePtr interface{}) error {
	transcoder := t.baseTranscoder
	if transcoder == nil {
		transcoder = gocb.NewJSONTranscoder()
	}

	valueType := reflect.TypeOf(valuePtr)
	for valueType.Kind() == reflect.Ptr {
		valueType = valueType.Elem()
	}
	if valueType.Kind() != reflect.Struct {
		return transcoder.Decode(data, flags, valuePtr)
	}

	var rawMap map[string]interface{}
	err := json.Unmarshal(data, &rawMap)
	if err != nil {
		return err
	}

	w := newWalker(defaultEncrypterAlias)
	encryptedPaths, err := w.Walk(valuePtr, false)
	if err != nil {
		return err
	}

	for _, p := range encryptedPaths {
		pathParts := p.pathParts
		basePath := pathParts[0]
		if len(pathParts) == 1 {
			mangledPath := t.mgr.Mangle(basePath)
			data, ok := rawMap[mangledPath].(map[string]interface{})
			if !ok {
				return errors.New("encryption block was not expected type")
			}
			res, err := t.mgr.Decrypt(data)
			if err != nil {
				return err
			}

			var resVal interface{}
			err = json.Unmarshal(res, &resVal)
			if err != nil {
				return err
			}

			delete(rawMap, mangledPath)
			rawMap[basePath] = resVal
			continue
		}

		rawMap[basePath], err = t.processDecryption(rawMap[basePath], pathParts[1:])
		if err != nil {
			return err
		}
	}

	b, err := json.Marshal(rawMap)
	if err != nil {
		return err
	}

	return transcoder.Decode(b, flags, valuePtr)
}

// Encodes a Go type into bytes for storage. Uses a base transcoder to do the actual JSON encoding, defaulting to
// the gocb default JSON transcoder.
func (t *Transcoder) Encode(value interface{}) ([]byte, uint32, error) {
	transcoder := t.baseTranscoder
	if transcoder == nil {
		transcoder = gocb.NewJSONTranscoder()
	}

	// First we encode the value down to raw bytes so that we can then read it back as a map.
	// We do this first so that the JSON encoder can handle any json tag issues like repeated tag names.
	data, flags, err := transcoder.Encode(value)
	if err != nil {
		return nil, 0, err
	}

	valueType := reflect.TypeOf(value)
	for valueType.Kind() == reflect.Ptr {
		valueType = valueType.Elem()
	}
	if valueType.Kind() != reflect.Struct {
		return data, flags, nil
	}

	// We walk the value type so that we can create a list of fields that we need to encrypt. We will only
	// list those fields which will be encoded to JSON and also have an encrypt tag - there's no point in encrypting
	// fields which aren't going to get written anyway.
	w := newWalker(defaultEncrypterAlias)
	encryptPaths, err := w.Walk(value, true)
	if err != nil {
		return nil, 0, err
	}

	// We then decode the bytes into a map of string to interface. If this fails then the base encoder probably hasn't
	// actually encoded the value to JSON.
	var rawMap map[string]interface{}
	err = json.Unmarshal(data, &rawMap)
	if err != nil {
		return nil, 0, err
	}

	// We go through the map accessing the parts that we need and replacing the value with the encrypted version.
	// We do this depth first so that we can encrypt any nested fields first.
	for _, p := range encryptPaths {
		pathParts := p.pathParts
		algo := p.algo
		basePath := pathParts[0]
		if len(pathParts) == 1 {
			b, err := json.Marshal(rawMap[basePath])
			if err != nil {
				return nil, 0, err
			}
			res, err := t.mgr.Encrypt(b, algo)
			if err != nil {
				return nil, 0, err
			}

			newPath := t.mgr.Mangle(basePath)
			delete(rawMap, basePath)
			rawMap[newPath] = res
			continue
		}

		rawMap[basePath], err = t.processEncryption(rawMap[basePath], pathParts[1:], algo)
		if err != nil {
			return nil, 0, err
		}
	}

	b, err := json.Marshal(rawMap)
	if err != nil {
		return nil, 0, err
	}

	return b, flags, nil
}

func (t *Transcoder) processEncryption(val interface{}, pathParts []string, algo string) (interface{}, error) {
	if len(pathParts) == 0 {
		b, err := json.Marshal(val)
		if err != nil {
			return nil, err
		}
		res, err := t.mgr.Encrypt(b, algo)
		if err != nil {
			return nil, err
		}

		return res, nil
	}
	currentPath := pathParts[0]
	if len(pathParts) == 1 {
		currentPath = t.mgr.Mangle(currentPath)
	}

	nextPathParts := pathParts[1:]
	switch typ := val.(type) {
	case map[string]interface{}:
		var err error
		typ[currentPath], err = t.processEncryption(typ[pathParts[0]], nextPathParts, algo)
		if err != nil {
			return nil, err
		}

		if len(nextPathParts) == 0 {
			delete(typ, pathParts[0])
		}

		return typ, nil
	case []interface{}:
		var err error
		i, err := strconv.Atoi(currentPath)
		if err != nil {
			return nil, err
		}
		typ[i], err = t.processEncryption(typ[i], nextPathParts, algo)
		if err != nil {
			return nil, err
		}
		return typ, nil
	}

	return nil, errors.New("type is not a map or slice and we are not at the end of our paths, this is likely a bug")
}

func (t *Transcoder) processDecryption(val interface{}, pathParts []string) (interface{}, error) {
	if len(pathParts) == 0 {
		data, ok := val.(map[string]interface{})
		if !ok {
			return nil, errors.New("encryption block was not expected type")
		}
		res, err := t.mgr.Decrypt(data)
		if err != nil {
			return nil, err
		}

		var resVal interface{}
		err = json.Unmarshal(res, &resVal)
		if err != nil {
			return nil, err
		}

		return resVal, nil
	}
	currentPath := pathParts[0]
	if len(pathParts) == 1 {
		currentPath = t.mgr.Mangle(currentPath)
	}

	nextPathParts := pathParts[1:]
	switch typ := val.(type) {
	case map[string]interface{}:
		var err error
		typ[pathParts[0]], err = t.processDecryption(typ[currentPath], nextPathParts)
		if err != nil {
			return nil, err
		}

		if len(nextPathParts) == 0 {
			delete(typ, currentPath)
		}
		return typ, nil
	case []interface{}:
		var err error
		i, err := strconv.Atoi(currentPath)
		if err != nil {
			return nil, err
		}

		typ[i], err = t.processDecryption(typ[i], nextPathParts)
		if err != nil {
			return nil, err
		}
		return typ, nil
	}

	return nil, errors.New("type is not a map or slice and we are not at the end of our paths, this is likely a bug")
}
