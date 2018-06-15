package gocbfieldcrypt

import (
	"github.com/pkg/errors"
)

type cryptoErrorCode uint16

const (
	CryptoProviderNotFound          = cryptoErrorCode(0x00)
	CryptoProviderMissingPublicKey  = cryptoErrorCode(0x01)
	CryptoProviderMissingSigningKey = cryptoErrorCode(0x02)
	CryptoProviderMissingPrivateKey = cryptoErrorCode(0x03)
	CryptoProviderSigningFailed     = cryptoErrorCode(0x04)
	CryptoProviderKeySize           = cryptoErrorCode(0x05)
)

type cryptoError struct {
	Code   cryptoErrorCode
	Reason string
}

func newCryptoError(code cryptoErrorCode, reason string) cryptoError {
	return cryptoError{
		Code:   code,
		Reason: reason,
	}
}

func (e cryptoError) Error() string {
	return e.Reason
}

// IsCryptoErrorType checks if an error corresponds to a given
// error code
func IsCryptoErrorType(err error, code cryptoErrorCode) bool {
	crypto, ok := errors.Cause(err).(cryptoError)
	if !ok {
		return false
	}

	if crypto.Code == code {
		return true
	}

	return false
}
