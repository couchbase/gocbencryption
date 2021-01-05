/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

package gocbfieldcrypt

import (
	"fmt"
	"github.com/pkg/errors"
)

type wrappedError struct {
	Message    string
	InnerError error
}

func (e wrappedError) Error() string {
	return fmt.Sprintf("%s: %s", e.Message, e.InnerError.Error())
}

func (e wrappedError) Unwrap() error {
	return e.InnerError
}

func wrapError(err error, message string) error {
	return wrappedError{
		Message:    message,
		InnerError: err,
	}
}

// Field level encryption Error Definitions RFC#64
var (
	// ErrCryptoKeyNotFound occurs when the specified key for encryption or decryption has not been registered.
	ErrCryptoKeyNotFound = errors.New("specified key is missing")

	// ErrInvalidCryptoKey occurs when the specified key for encryption or decryption is not valid.
	ErrInvalidCryptoKey = errors.New("specified key is invalid")

	// ErrDecrypterNotFound occurs when a message cannot be decrypted because there is no decrypter registered for
	// the algorithm specified.
	ErrDecrypterNotFound = errors.New("decrypter not found")

	// ErrEncrypterNotFound occurs when a message cannot be encrypted because there is no encrypter registered for
	// the algorithm specified.
	ErrEncrypterNotFound = errors.New("encrypter not found")

	// ErrInvalidCipherText occurs when decryption fails due to malformed input, integrity check failure, etc...
	ErrInvalidCipherText = errors.New("invalid cipher text")
)

// CryptoError represents a generic cryptography failure.
type CryptoError struct {
	InnerError error
}

func (e CryptoError) Error() string {
	return "generic crypto failure | " + e.InnerError.Error()
}

func (e CryptoError) Unwrap() error {
	return e.InnerError
}

// EncryptionError represents an encryption failure.
type EncryptionError struct {
	InnerError error
}

func (e EncryptionError) Error() string {
	return "encryption failure | " + e.InnerError.Error()
}

func (e EncryptionError) Unwrap() error {
	return e.InnerError
}

// DecryptionError represents a decryption failure.
type DecryptionError struct {
	InnerError error
}

func (e DecryptionError) Error() string {
	return "decryption failure | " + e.InnerError.Error()
}

func (e DecryptionError) Unwrap() error {
	return e.InnerError
}
