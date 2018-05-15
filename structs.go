/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

package gocbfieldcrypt

import (
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
)

type field struct {
	algorithm string
	options   []string
}

var fieldCache struct {
	value atomic.Value // map[reflect.Type]map[string]field
	mu    sync.Mutex   // used only by writers
}

func typeFields(t reflect.Type) map[string]field {
	fields := make(map[string]field)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("cbcrypt")
		if tag == "" || tag == "-" {
			continue
		}

		fieldName := f.Name
		jsonTag := f.Tag.Get("json")
		if jsonTag == "-" {
			continue
		}
		if jsonTag != "" {
			jsonOpts := strings.Split(jsonTag, ",")
			fieldName = jsonOpts[0]
		}

		options := strings.Split(tag, ",")
		fields[fieldName] = field{
			algorithm: options[0],
			options:   options[1:],
		}
	}

	return fields
}

func cachedTypeFields(t reflect.Type) map[string]field {
	m, _ := fieldCache.value.Load().(map[reflect.Type]map[string]field)
	f := m[t]
	if f != nil {
		return f
	}

	// Compute fields without lock.
	// Might duplicate effort but won't hold other computations back.
	f = typeFields(t)
	if f == nil {
		f = map[string]field{}
	}

	fieldCache.mu.Lock()
	m, _ = fieldCache.value.Load().(map[reflect.Type]map[string]field)
	newM := make(map[reflect.Type]map[string]field, len(m)+1)
	for k, v := range m {
		newM[k] = v
	}
	newM[t] = f
	fieldCache.value.Store(newM)
	fieldCache.mu.Unlock()
	return f
}

func typeProviders(t reflect.Type, keys KeyProvider) (map[string]CryptoProvider, error) {
	out := make(map[string]CryptoProvider)
	fields := cachedTypeFields(t)
	for fname, f := range fields {
		provider, err := providerFromField(f, keys)
		if err != nil {
			return nil, err
		}

		out[fname] = provider
	}
	return out, nil
}
