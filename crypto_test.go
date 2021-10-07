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

func TestDefaultCryptoManager_CanHaveOnlyOneDecrypter(t *testing.T) {
	iv := []byte{0x1a, 0xf3, 0x8c, 0x2d, 0xc2, 0xb9, 0x6f, 0xfd, 0xd8, 0x66, 0x94, 0x09, 0x23, 0x41, 0xbc, 0x04}

	key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	}

	keyring := &InsecureKeyring{
		keys: map[string]Key{
			"test-key": {
				ID:    "test-key",
				Bytes: key,
			},
		},
	}

	provider := NewAeadAes256CbcHmacSha512Provider(keyring)

	mgr := NewDefaultCryptoManager(nil)

	defaultEncrypter := provider.EncrypterForKey("test-key")
	defaultEncrypter.iv = iv
	err := mgr.RegisterEncrypter("one", defaultEncrypter)
	if err != nil {
		t.Fatalf("Failed to register encrypter: %v", err)
	}

	err = mgr.RegisterDecrypter(provider.Decrypter())
	if err != nil {
		t.Fatalf("Failed to register decrypter: %v", err)
	}

	err = mgr.RegisterDecrypter(provider.Decrypter())
	if err == nil {
		t.Fatalf("Register decrypter is supposed to fail but it did not")
	}
}
