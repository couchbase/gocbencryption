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
	switch valueType.Kind() {
	case reflect.Struct:
	case reflect.Map:
	case reflect.Slice:
	default:
		return transcoder.Decode(data, flags, valuePtr)
	}

	var raw interface{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	w := newWalker(defaultEncrypterAlias, false)
	encryptedPaths, err := w.Walk(valuePtr)
	if err != nil {
		return err
	}

	err = t.decodeElem(raw, encryptedPaths)
	if err != nil {
		return err
	}

	b, err := json.Marshal(raw)
	if err != nil {
		return err
	}

	return transcoder.Decode(b, flags, valuePtr)
}

func (t *Transcoder) decodeElem(raw interface{}, encryptedPaths []encryptPath) error {
	var rawMap map[string]interface{}
	switch rawT := raw.(type) {
	case []interface{}:
		for i := range rawT {
			var err error
			err = t.decodeElem(rawT[i], encryptedPaths)
			if err != nil {
				return err
			}
		}
		return nil
	case map[string]interface{}:
		rawMap = rawT
	default:
		return errors.New("unexpected data type")
	}

	for _, p := range encryptedPaths {
		pathParts := p.pathParts
		basePath := pathParts[0]
		if len(pathParts) == 1 {
			mangledPath := t.mgr.Mangle(basePath)
			resVal, err := t.processDecryption(rawMap[mangledPath], []string{})
			if err != nil {
				return err
			}

			delete(rawMap, mangledPath)
			rawMap[basePath] = resVal
			continue
		}

		if pathParts[0] == anonymousMap {
			for k, v := range rawMap {
				var err error
				rawMap[k], err = t.processDecryption(v, pathParts[1:])
				if err != nil {
					return err
				}
			}
		} else {
			var err error
			rawMap[basePath], err = t.processDecryption(rawMap[basePath], pathParts[1:])
			if err != nil {
				return err
			}
		}
	}

	return nil
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
	switch valueType.Kind() {
	case reflect.Struct:
	case reflect.Map:
	case reflect.Slice:
	default:
		return transcoder.Encode(data)
	}

	// We walk the value type so that we can create a list of fields that we need to encrypt. We will only
	// list those fields which will be encoded to JSON and also have an encrypt tag - there's no point in encrypting
	// fields which aren't going to get written anyway.
	w := newWalker(defaultEncrypterAlias, true)
	encryptPaths, err := w.Walk(value)
	if err != nil {
		return nil, 0, err
	}

	// We then decode the bytes into a map of string to interface. If this fails then the base encoder probably hasn't
	// actually encoded the value to JSON.
	var rawMap interface{}
	err = json.Unmarshal(data, &rawMap)
	if err != nil {
		return nil, 0, err
	}

	err = t.encodeElem(rawMap, encryptPaths)
	if err != nil {
		return nil, 0, err
	}

	b, err := json.Marshal(rawMap)
	if err != nil {
		return nil, 0, err
	}

	return b, flags, nil
}

func (t *Transcoder) encodeElem(raw interface{}, encryptedPaths []encryptPath) error {
	var rawMap map[string]interface{}
	switch rawT := raw.(type) {
	case []interface{}:
		for i := range rawT {
			var err error
			err = t.encodeElem(rawT[i], encryptedPaths)
			if err != nil {
				return err
			}
		}
		return nil
	case map[string]interface{}:
		rawMap = rawT
	default:
		return errors.New("unexpected data type")
	}
	// We go through the map accessing the parts that we need and replacing the value with the encrypted version.
	// We do this depth first so that we can encrypt any nested fields first.
	for _, p := range encryptedPaths {
		pathParts := p.pathParts
		algo := p.algo
		basePath := pathParts[0]
		if len(pathParts) == 1 {
			b, err := json.Marshal(rawMap[basePath])
			if err != nil {
				return err
			}
			res, err := t.mgr.Encrypt(b, algo)
			if err != nil {
				return err
			}

			newPath := t.mgr.Mangle(basePath)
			delete(rawMap, basePath)
			rawMap[newPath] = res
			continue
		}

		if pathParts[0] == anonymousMap {
			for k, v := range rawMap {
				var err error
				rawMap[k], err = t.processEncryption(v, pathParts[1:], algo)
				if err != nil {
					return err
				}
			}
		} else {
			var err error
			rawMap[basePath], err = t.processEncryption(rawMap[basePath], pathParts[1:], algo)
			if err != nil {
				return err
			}
		}
	}

	return nil
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

	if pathParts[0] == anonymousMap {
		if val == nil {
			return val, nil
		}
		// This has to be a map, if it isn't then something naughty has happened.
		vAssert, ok := val.(map[string]interface{})
		if !ok {
			return nil, errors.New("unexpected value found when expecting a golang map type")
		}
		for k, v := range vAssert {
			var err error
			vAssert[k], err = t.processEncryption(v, pathParts[1:], algo)
			if err != nil {
				return nil, err
			}
		}
		return val, nil
	}

	switch typ := val.(type) {
	case map[string]interface{}:
		currentPath := pathParts[0]
		if len(pathParts) == 1 {
			currentPath = t.mgr.Mangle(currentPath)
		}

		nextPathParts := pathParts[1:]

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
		for i := range typ {
			var err error
			typ[i], err = t.processEncryption(typ[i], pathParts, algo)
			if err != nil {
				return nil, err
			}
		}
		return typ, nil
	case nil:
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

	if pathParts[0] == anonymousMap {
		if val == nil {
			return val, nil
		}
		// This has to be a map, if it isn't then something naughty has happened.
		vAssert, ok := val.(map[string]interface{})
		if !ok {
			return nil, errors.New("unexpected value found when expecting a golang map type")
		}
		for k, v := range vAssert {
			var err error
			vAssert[k], err = t.processDecryption(v, pathParts[1:])
			if err != nil {
				return nil, err
			}
		}
		return val, nil
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
		for i := range typ {
			var err error
			typ[i], err = t.processDecryption(typ[i], pathParts)
			if err != nil {
				return nil, err
			}
		}
		return typ, nil
	case nil:
		return typ, nil
	}

	return nil, errors.New("type is not a map or slice and we are not at the end of our paths, this is likely a bug")
}
