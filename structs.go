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

var fields map[string]field

//Converts the passed reflect type to a slice or map before passing back to the handleTypeRedirect as a struct
func checkMapOrSliceForEncryption(t reflect.Type, p string) {

	//Get the actual object of the slice or map from the pointer
	ov := t.Elem()

	//Re-check it
	handleTypeRediret(ov, p)
}

//Send the relfect type to the proper handler
func handleTypeRediret(t reflect.Type, p string) {

	switch t.Kind() {
	case reflect.Struct:
		typeFields(t, p)
	case reflect.Slice:
		checkMapOrSliceForEncryption(t, p)
	case reflect.Map:
		checkMapOrSliceForEncryption(t, p)
	}
}

//Loops through the top level struct looking for any crypt tagged elements
//Hands off any second level structs and non-structs to a handler method to pre-process the non-structs
func typeFields(t reflect.Type, p string) map[string]field {
	if len(fields) == 0 {
		fields = make(map[string]field)
	}

	//Keep track of whether to use the f.Name as a parent path
	//f.Name should not be used as a parent path if a json tag is not setup as the non-json name will not exist in the doc path during encryption and decryption
	var useFieldNameAsParent bool

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)

		tag := f.Tag.Get("cbcrypt")

		fieldName := f.Name
		useFieldNameAsParent = false

		jsonTag := f.Tag.Get("json")
		if jsonTag == "-" {
			continue
		}
		if jsonTag != "" {
			jsonOpts := strings.Split(jsonTag, ",")
			fieldName = jsonOpts[0]

			//Add the parent path if one is provided

			if p != "" {
				fieldName = p + "." + fieldName
			}

			useFieldNameAsParent = true

		}

		if tag == "" || tag == "-" {

			//If this is a struct without a crypt tag check to see if any of its elements are encrypted
			if fieldName != "" {
				if !useFieldNameAsParent {
					fieldName = ""
				}
				handleTypeRediret(f.Type, fieldName)
			}

			continue
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
	f = typeFields(t, "")
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

func typeProviders(t reflect.Type, providers map[string]CryptoProvider) (map[string]CryptoProvider, error) {
	out := make(map[string]CryptoProvider)
	fields := cachedTypeFields(t)
	for fname, f := range fields {
		provider, err := providerFromField(f, providers)
		if err != nil {
			return nil, err
		}

		out[fname] = provider
	}
	return out, nil
}
