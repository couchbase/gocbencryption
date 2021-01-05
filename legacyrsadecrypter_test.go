/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */
package gocbfieldcrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
)

func TestLegacyRsaCryptoProvider(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	rsaPrivateKey, err := marshalPKCS1PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}
	rsaPublicKey, err := marshalPKCS1PublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	type testSubStruct struct {
		TestString string
		TestNum    int
	}

	type testCryptStruct struct {
		CryptoStruct testSubStruct `cbcrypt:"myrsaprovider"`
	}

	expected := testCryptStruct{
		CryptoStruct: testSubStruct{
			TestString: "Franklyn",
			TestNum:    1448,
		},
	}

	keyStore := &InsecureKeyring{
		keys: map[string]Key{
			"rsaprivkey": {
				ID:    "rsaprivkey",
				Bytes: rsaPrivateKey,
			},
			"rsapubkey": {
				ID:    "rsapubkey",
				Bytes: rsaPublicKey,
			},
		},
	}

	provider := NewLegacyRsaCryptoProvider(keyStore, "rsapubkey", "rsaprivkey")

	encB, err := json.Marshal(expected)
	if err != nil {
		t.Fatalf("Marshal failed with error: %v", err)
	}

	testEncDoc, err := provider.encrypt(encB)
	if err != nil {
		t.Fatalf("Encrypt failed with error: %v", err)
	}

	b, err := provider.Decrypt(testEncDoc)
	if err != nil {
		t.Fatalf("Decrypt failed with error: %v", err)
	}

	var actual testCryptStruct
	err = json.Unmarshal(b, &actual)
	if err != nil {
		t.Fatalf("Unmarshal failed with error: %v", err)
	}

	if actual != expected {
		t.Fatalf("Expected message to be %v but was %v", expected, actual)
	}
}
