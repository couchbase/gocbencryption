package gocbfieldcrypt

import (
	"testing"

	"github.com/pkg/errors"
)

func TestIsCryptoErrorType(t *testing.T) {
	err := newCryptoError(CryptoProviderNotFound, "some message")

	if !IsCryptoErrorType(err, CryptoProviderNotFound) {
		t.Fatalf("Expected CryptoProviderNotFound but was %v", err)
	}
}

func TestIsCryptoErrorTypeWrapped(t *testing.T) {
	err := newCryptoError(CryptoProviderNotFound, "some message")
	newErr := errors.Wrap(err, "some wrapper")

	if !IsCryptoErrorType(newErr, CryptoProviderNotFound) {
		t.Fatalf("Expected CryptoProviderNotFound but was %v", err)
	}
}
