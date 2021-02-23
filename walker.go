/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

package gocbfieldcrypt

import (
	"fmt"
	"github.com/mitchellh/reflectwalk"
	"reflect"
	"sort"
)

// Empty string isn't a valid json fieldname so we're safe to use this for special casing when a field contains
// an actual golang map type.
const anonymousMap = ""

type encryptPathSorter struct {
	paths   []encryptPath
	sortAsc bool
}

func (p encryptPathSorter) Len() int {
	return len(p.paths)
}

func (p encryptPathSorter) Less(i, j int) bool {
	if p.sortAsc {
		return len(p.paths[i].pathParts) > len(p.paths[j].pathParts)
	}
	return len(p.paths[i].pathParts) < len(p.paths[j].pathParts)
}

func (p encryptPathSorter) Swap(i, j int) { p.paths[i], p.paths[j] = p.paths[j], p.paths[i] }

type encryptPath struct {
	pathParts []string
	algo      string
}

// Walker will walk through an interface and find any fields which will be JSON encoded and are tagged with "encrypted".
// This includes fields which do not have a json tag but are exported and have the encrypted tag.
// The walker does not attempt to do any sort of JSON tag validation, that is the responsibility of the JSON encoder.
type walker struct {
	encryptPaths []encryptPath
	currentPath  []string
	defaultAlias string
	sortAsc      bool
}

func newWalker(defaultAlias string, sortAsc bool) *walker {
	return &walker{
		defaultAlias: defaultAlias,
		sortAsc:      sortAsc,
	}
}

// Walk walks over the structure of the data and extracts any paths that should be encrypted.
// The returned string slice is sorted in increasing order meaning that deeper paths come before their parents.
func (w *walker) Walk(data interface{}) ([]encryptPath, error) {
	v := reflect.ValueOf(data)
	val := data
	if v.Kind() == reflect.Ptr {
		val = reflect.Indirect(v).Interface()
	}
	tv := reflect.New(reflect.TypeOf(val)).Interface()

	return w.walk(tv)
}

func (w *walker) walk(data interface{}) ([]encryptPath, error) {
	if err := reflectwalk.Walk(data, w); err != nil {
		return nil, err
	}

	sort.Sort(encryptPathSorter{
		paths:   w.encryptPaths,
		sortAsc: w.sortAsc,
	})

	return w.encryptPaths, nil
}

func (w *walker) Enter(l reflectwalk.Location) error {
	return nil
}

func (w *walker) Exit(l reflectwalk.Location) error {
	if l == reflectwalk.StructField || l == reflectwalk.ArrayElem || l == reflectwalk.SliceElem ||
		l == reflectwalk.MapValue {
		w.currentPath = w.currentPath[:len(w.currentPath)-1]
	}
	return nil
}

func (w *walker) Array(v reflect.Value) error {
	return nil
}

func (w *walker) ArrayElem(i int, v reflect.Value) error {
	w.currentPath = append(w.currentPath, fmt.Sprintf("%d", i))
	return nil
}

func (w *walker) Interface(v reflect.Value) error {
	return nil
}

func (w *walker) Map(v reflect.Value) error {
	walker := newWalker(w.defaultAlias, w.sortAsc)
	paths, err := walker.walk(reflect.New(v.Type().Elem()).Interface())
	if err != nil {
		return err
	}

	for _, path := range paths {
		path.pathParts = append([]string{anonymousMap}, path.pathParts...)
		path.pathParts = append(w.currentPath, path.pathParts...)
		w.encryptPaths = append(w.encryptPaths, path)
	}
	return nil
}

func (w *walker) MapElem(m, k, v reflect.Value) error {
	return nil
}

func (w *walker) Slice(v reflect.Value) error {
	walker := newWalker(w.defaultAlias, w.sortAsc)
	paths, err := walker.walk(reflect.New(v.Type().Elem()).Interface())
	if err != nil {
		return err
	}

	for _, path := range paths {
		path.pathParts = append(w.currentPath, path.pathParts...)
		w.encryptPaths = append(w.encryptPaths, path)
	}
	return nil
}

func (w *walker) SliceElem(i int, v reflect.Value) error {
	return nil
}

func (w *walker) Struct(v reflect.Value) error {
	return nil
}

func (w *walker) StructField(f reflect.StructField, v reflect.Value) error {
	if f.PkgPath != "" {
		return reflectwalk.SkipEntry
	}
	jsonTag := f.Tag.Get("json")
	if jsonTag == "" || jsonTag == "-" {
		return reflectwalk.SkipEntry
	}
	w.currentPath = append(w.currentPath, jsonTag)
	alias, ok := f.Tag.Lookup("encrypted")
	if ok {
		if alias == "" {
			alias = w.defaultAlias
		}

		currentPath := make([]string, len(w.currentPath))
		copy(currentPath, w.currentPath)
		w.encryptPaths = append(w.encryptPaths,
			encryptPath{
				pathParts: currentPath,
				algo:      alias,
			})
	}
	return nil
}
