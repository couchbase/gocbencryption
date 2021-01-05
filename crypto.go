/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

package gocbfieldcrypt

import (
	"errors"
	"strings"
)

const defaultEncrypterAlias = "__DEFAULT__"

// Key is the representation of an encryption key.
type Key struct {
	ID    string
	Bytes []byte
}

// Keyring provides access to encryption keys.
type Keyring interface {
	Get(keyID string) (Key, error)
}

// InsecureKeyring is an implementation of Keyring that stores keys in memory.
type InsecureKeyring struct {
	keys map[string]Key
}

func NewInsecureKeyring() *InsecureKeyring {
	return &InsecureKeyring{
		keys: make(map[string]Key),
	}
}

// Add adds a key to the keyring, overwriting any key that already exists with the given ID.
func (ks *InsecureKeyring) Add(key Key) {
	ks.keys[key.ID] = key
}

// Get retrives the Key for a given id from the keyring.
func (ks *InsecureKeyring) Get(keyID string) (Key, error) {
	if key, ok := ks.keys[keyID]; ok {
		return key, nil
	}
	return Key{}, ErrCryptoKeyNotFound
}

// Decrypter is responsible for performing decryption for a specific algorithm.
type Decrypter interface {
	// Algorithm returns the name of the algorithm handled by this Decrypter.
	Algorithm() string

	// Decrypt performs decryption of an EncryptionResult into plaintext.
	Decrypt(*EncryptionResult) ([]byte, error)
}

// Encrypter is responsible for performing encryption for a specific algorithm and encryption key.
type Encrypter interface {
	// Encrypt performs encryption of a plaintext.
	Encrypt(plaintext []byte) (*EncryptionResult, error)
}

// CryptoManager is responsible for the management of encryption and decryption of data.
type CryptoManager interface {
	Encrypt(plaintext []byte, encrypterAlias string) (map[string]interface{}, error)
	Decrypt(encrypted map[string]interface{}) ([]byte, error)
	Mangle(fieldName string) string
	Demangle(fieldName string) string
	IsMangled(fieldName string) bool
}

// DefaultCryptoManagerOptions are the options available when creating a DefaultCryptoManager.
type DefaultCryptoManagerOptions struct {
	// EncryptedFieldPrefix specifies the string to prepend to a JSON Object's field name to indicate the field
	// holds an encrypted value.
	//
	// There is usually no need to call this method unless you are upgrading from version 1.x of this library,
	// in which case you should set the encrypted field name prefix to "__crypt_".
	// (The default value changed in version 2.0 to avoid conflicts with Couchbase Sync Gateway which does not
	// allow field names to start with an underscore.)
	EncryptedFieldPrefix string
}

// DefaultCryptoManager is the default implementation of CryptoManager.
type DefaultCryptoManager struct {
	encryptedFieldPrefix string
	aliasToEncrypter     map[string]Encrypter
	algoToDecrypter      map[string]Decrypter
}

// NewDefaultCryptoManager creates a new DefaultCryptoManager.
func NewDefaultCryptoManager(opts *DefaultCryptoManagerOptions) *DefaultCryptoManager {
	if opts == nil {
		opts = &DefaultCryptoManagerOptions{}
	}

	prefix := opts.EncryptedFieldPrefix
	if prefix == "" {
		prefix = "encrypted$"
	}

	return &DefaultCryptoManager{
		encryptedFieldPrefix: prefix,
		aliasToEncrypter:     make(map[string]Encrypter),
		algoToDecrypter:      make(map[string]Decrypter),
	}
}

// RegisterEncrypter registers a new Encrypter with the manager, the alias is used by the Encrypt function to
// determine which Encrypter to use based on the field tag.
func (mgr *DefaultCryptoManager) RegisterEncrypter(alias string, encrypter Encrypter) error {
	if _, ok := mgr.aliasToEncrypter[alias]; ok {
		return errors.New("alias is already registered to an encrypter")
	}

	mgr.aliasToEncrypter[alias] = encrypter
	return nil
}

// RegisterDecrypter registers a new Decrypter with the manager, unlike RegisterEncrypter this function does not
// have an alias parameter - the algorithm written as a part of the field data is used to determine the Decrypter
// to use.
func (mgr *DefaultCryptoManager) RegisterDecrypter(decrypter Decrypter) error {
	if _, ok := mgr.algoToDecrypter[decrypter.Algorithm()]; ok {
		return errors.New("algorithm is already registered to a decrypter")
	}

	mgr.algoToDecrypter[decrypter.Algorithm()] = decrypter
	return nil
}

// DefaultEncrypter registers a default encrypter with the manager. This Encrypter is used if the encrypted tag is used
// with no value.
func (mgr *DefaultCryptoManager) DefaultEncrypter(encrypter Encrypter) error {
	return mgr.RegisterEncrypter(defaultEncrypterAlias, encrypter)
}

// Encrypt uses the provided encrypter alias to the encrypt the plaintext with the corresponding Encrypter.
func (mgr *DefaultCryptoManager) Encrypt(plaintext []byte, encrypterAlias string) (map[string]interface{}, error) {
	if encrypterAlias == "" {
		encrypterAlias = defaultEncrypterAlias
	}
	e, ok := mgr.aliasToEncrypter[encrypterAlias]
	if !ok {
		return nil, EncryptionError{
			InnerError: ErrEncrypterNotFound,
		}
	}

	res, err := e.Encrypt(plaintext)
	if err != nil {
		return nil, EncryptionError{
			InnerError: err,
		}
	}

	return res.AsMap(), nil
}

// Decrypt decrypts the provided data.
func (mgr *DefaultCryptoManager) Decrypt(encrypted map[string]interface{}) ([]byte, error) {
	eRes := NewEncryptionResultFromMap(encrypted)
	algo, err := eRes.Algorithm()
	if err != nil {
		return nil, DecryptionError{
			InnerError: err,
		}
	}

	de, ok := mgr.algoToDecrypter[algo]
	if !ok {
		return nil, DecryptionError{
			InnerError: ErrDecrypterNotFound,
		}
	}

	b, err := de.Decrypt(eRes)
	if err != nil {
		return nil, DecryptionError{
			InnerError: err,
		}
	}

	return b, nil
}

// Mangle applies the encryption field prefix to the field name.
func (mgr *DefaultCryptoManager) Mangle(fieldName string) string {
	return mgr.encryptedFieldPrefix + fieldName
}

// Demangle removes the encryption field prefix from the field name.
func (mgr *DefaultCryptoManager) Demangle(fieldName string) string {
	return strings.TrimPrefix(fieldName, mgr.encryptedFieldPrefix)
}

// IsMangled determines whether or not the field name is mangled with the encryption field prefix.
func (mgr *DefaultCryptoManager) IsMangled(fieldName string) bool {
	return strings.HasPrefix(fieldName, mgr.encryptedFieldPrefix)
}
