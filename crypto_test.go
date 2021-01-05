package gocbfieldcrypt

import (
	"errors"
	"testing"
)

func TestDefaultCryptoManager_DecryptResultMissingAlg(t *testing.T) {
	d := map[string]interface{}{
		"kid":        "mytestkey",
		"ciphertext": "GvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4RLzoaAtJihk=",
	}

	mgr := NewDefaultCryptoManager(nil)

	_, err := mgr.Decrypt(d)
	if err == nil {
		t.Fatalf("Error should not have been nil")
	}
}

func TestDefaultCryptoManager_DecryptResultInvalidAlgType(t *testing.T) {
	d := map[string]interface{}{
		"kid":        "mytestkey",
		"alg":        []string{"thing"},
		"ciphertext": "GvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4RLzoaAtJihk=",
	}

	mgr := NewDefaultCryptoManager(nil)

	_, err := mgr.Decrypt(d)
	if err == nil {
		t.Fatalf("Error should not have been nil")
	}
}

func TestDefaultCryptoManager_DecryptMissingDecrypter(t *testing.T) {
	d := map[string]interface{}{
		"alg":        "AEAD_AES_256_CBC_HMAC_SHA512",
		"kid":        "mytestkey",
		"ciphertext": "GvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4RLzoaAtJihk=",
	}

	mgr := NewDefaultCryptoManager(nil)

	_, err := mgr.Decrypt(d)
	if !errors.Is(err, ErrDecrypterNotFound) {
		t.Fatalf("Error should have been decrypter not found, was: %v", err)
	}
}

func TestDefaultCryptoManager_EncryptMissingEncrypter(t *testing.T) {
	mgr := NewDefaultCryptoManager(nil)

	_, err := mgr.Encrypt([]byte("sometext"), "idontexist")
	if !errors.Is(err, ErrEncrypterNotFound) {
		t.Fatalf("Error should have been encrypter not found, was: %v", err)
	}
}

func TestDefaultCryptoManager_Mangle(t *testing.T) {
	field := "test"
	mgr := NewDefaultCryptoManager(nil)
	mangled := mgr.Mangle(field)
	if mangled != "encrypted$test" {
		t.Fatalf("Expected encrypted$test but was %s", mangled)
	}
}

func TestDefaultCryptoManager_MangleCustom(t *testing.T) {
	field := "test"
	mgr := NewDefaultCryptoManager(&DefaultCryptoManagerOptions{
		EncryptedFieldPrefix: "__crypt_",
	})
	mangled := mgr.Mangle(field)
	if mangled != "__crypt_test" {
		t.Fatalf("Expected __crypt_test but was %s", mangled)
	}
}

func TestDefaultCryptoManager_Demangle(t *testing.T) {
	field := "encrypted$test"
	mgr := NewDefaultCryptoManager(nil)
	mangled := mgr.Demangle(field)
	if mangled != "test" {
		t.Fatalf("Expected test but was %s", mangled)
	}
}

func TestDefaultCryptoManager_DemangleCustom(t *testing.T) {
	field := "__crypt_test"
	mgr := NewDefaultCryptoManager(&DefaultCryptoManagerOptions{
		EncryptedFieldPrefix: "__crypt_",
	})
	mangled := mgr.Demangle(field)
	if mangled != "test" {
		t.Fatalf("Expected test but was %s", mangled)
	}
}

func TestDefaultCryptoManager_IsMangled(t *testing.T) {
	mgr := NewDefaultCryptoManager(nil)
	if !mgr.IsMangled("encrypted$test") {
		t.Fatalf("Expected field to be reported as mangled")
	}

	if mgr.IsMangled("test") {
		t.Fatalf("Expected field to be reported as not mangled")
	}
}

func TestDefaultCryptoManager_IsMangledCustom(t *testing.T) {

	mgr := NewDefaultCryptoManager(&DefaultCryptoManagerOptions{
		EncryptedFieldPrefix: "__crypt_",
	})
	if !mgr.IsMangled("__crypt_test") {
		t.Fatalf("Expected field to be reported as mangled")
	}

	if mgr.IsMangled("test") {
		t.Fatalf("Expected field to be reported as not mangled")
	}
}
