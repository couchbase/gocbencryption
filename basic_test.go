/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

package gocbfieldcrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
)

type testSubStruct struct {
	TestString string
	TestNum    int
}

type testCryptStruct struct {
	NoCrypt      string
	CryptString  string        `cbcrypt:"myAESProvider"`
	CryptNum     int           `cbcrypt:"myAESProvider"`
	CryptoStruct testSubStruct `cbcrypt:"myRSAProvider"`
}

func TestJsonStruct(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaPrivateKey := marshalPKCS1PrivateKey(rsaKey)
	rsaPublicKey := marshalPKCS1PublicKey(&rsaKey.PublicKey)

	testKey, _ := hex.DecodeString("1234567890123456123456789012345612345678901234561234567890123456")
	keyStore := &InsecureKeystore{
		Keys: map[string][]byte{
			"somekey":    testKey,
			"hmackey":    testKey,
			"rsaprivkey": rsaPrivateKey,
			"rsapubkey":  rsaPublicKey,
		},
	}

	aesProvider := &AesCryptoProvider{
		Alias:    "myAESProvider",
		KeyStore: keyStore,
		Key:      "somekey",
		HmacKey:  "hmackey",
	}

	rsaProvider := &RsaCryptoProvider{
		Alias:      "myRSAProvider",
		KeyStore:   keyStore,
		PublicKey:  "rsapubkey",
		PrivateKey: "rsaprivkey",
	}

	testObj := testCryptStruct{
		NoCrypt:     "Hello",
		CryptString: "World",
		CryptNum:    1337,
		CryptoStruct: testSubStruct{
			TestString: "Franklyn",
			TestNum:    1448,
		},
	}

	bytes, err := json.Marshal(testObj)
	if err != nil {
		t.Fatalf("Failed to marshal: %s", err)
	}

	providers := make(map[string]CryptoProvider)
	providers["myAESProvider"] = aesProvider
	providers["myRSAProvider"] = rsaProvider

	encBytes, err := EncryptJsonStruct(bytes, reflect.TypeOf(testObj), providers)
	if err != nil {
		t.Fatalf("Failed to encrypt: %s", err)
	}

	decBytes, err := DecryptJsonStruct(encBytes, reflect.TypeOf(testObj), providers)
	if err != nil {
		t.Fatalf("Failed to decrypt: %s", err)
	}

	var decData testCryptStruct
	err = json.Unmarshal(decBytes, &decData)
	if err != nil {
		t.Fatalf("Failed to unmarshal decrypted document: %s", err)
	}

	if !reflect.DeepEqual(testObj, decData) {
		t.Fatalf("Decrypted document did not match original")
	}
}

type testCrossSDKStruct struct {
	Message string `cbcrypt:"myAESProvider" json:"message"`
}

func TestInterSDKAES(t *testing.T) {
	testDoc := testCrossSDKStruct{
		Message: "The old grey goose jumped over the wrickety gate.",
	}

	testEncDoc := map[string]interface{}{
		"__crypt_message": cipherData{
			Algorithm:  "AES-256-HMAC-SHA256",
			KeyId:      "mypublickey",
			Iv:         "Cfq84/46Qjet3EEQ1HUwSg==",
			Ciphertext: "sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==",
			Signature:  "rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM=",
		},
	}

	encDataBytes, err := json.Marshal(testEncDoc)
	if err != nil {
		t.Fatalf("Failed to serialize test data: %s", err)
	}

	keyStore := &InsecureKeystore{
		Keys: map[string][]byte{
			"mypublickey": []byte("!mysecretkey#9^5usdk39d&dlf)03sL"),
			"myhmackey":   []byte("myauthpassword"),
		},
	}

	aesProvider := &AesCryptoProvider{
		Alias:    "myAESProvider",
		KeyStore: keyStore,
		Key:      "mypublickey",
		HmacKey:  "myhmackey",
	}

	providers := make(map[string]CryptoProvider)
	providers["myAESProvider"] = aesProvider

	decData, err := DecryptJsonStruct(encDataBytes, reflect.TypeOf(testDoc), providers)
	if err != nil {
		t.Fatalf("Failed to decrypt test data: %s", err)
	}

	var decDoc testCrossSDKStruct
	err = json.Unmarshal(decData, &decDoc)
	if err != nil {
		t.Fatalf("Failed to unmarshall test data: %s", err)
	}

	if !reflect.DeepEqual(testDoc, decDoc) {
		t.Fatalf("Decrypted document did not match original")
	}
}

func TestInvalidProvider(t *testing.T) {
	invalidCryptStruct := struct {
		CryptString string `cbcrypt:"thisdoesntexist"`
	}{
		"something",
	}

	bytes, err := json.Marshal(invalidCryptStruct)
	if err != nil {
		t.Fatalf("Failed to marshal: %s", err)
	}

	providers := make(map[string]CryptoProvider)

	_, err = EncryptJsonStruct(bytes, reflect.TypeOf(invalidCryptStruct), providers)
	if err == nil || !IsCryptoErrorType(err, CryptoProviderNotFound) {
		t.Fatalf("Expected invalid provider error, was: %s", err)
	}
}

func TestMissingPublicKey(t *testing.T) {
	invalidCryptStruct := struct {
		CryptString string `cbcrypt:"aes256"`
	}{
		"something",
	}

	bytes, err := json.Marshal(invalidCryptStruct)
	if err != nil {
		t.Fatalf("Failed to marshal: %s", err)
	}

	testKey, _ := hex.DecodeString("1234567890123456123456789012345612345678901234561234567890123456")
	keyStore := &InsecureKeystore{
		Keys: map[string][]byte{
			"publickey": testKey,
			"hmackey":   testKey,
		},
	}

	aesProvider := &AesCryptoProvider{
		Alias:    "myAESProvider",
		KeyStore: keyStore,
		HmacKey:  "hmackey",
	}

	providers := make(map[string]CryptoProvider)
	providers["aes256"] = aesProvider

	_, err = EncryptJsonStruct(bytes, reflect.TypeOf(invalidCryptStruct), providers)
	if err == nil || !IsCryptoErrorType(err, CryptoProviderMissingPublicKey) {
		t.Fatalf("Expected missing public key error, was: %s", err)
	}
}

func TestMissingPrivateKey(t *testing.T) {
	invalidCryptStruct := struct {
		CryptString string `cbcrypt:"aes256,publickey"`
	}{
		"something",
	}

	bytes, err := json.Marshal(invalidCryptStruct)
	if err != nil {
		t.Fatalf("Failed to marshal: %s", err)
	}

	testKey, _ := hex.DecodeString("1234567890123456123456789012345612345678901234561234567890123456")
	keyStore := &InsecureKeystore{
		Keys: map[string][]byte{
			"publickey": testKey,
			"hmackey":   testKey,
		},
	}

	aesProvider := &AesCryptoProvider{
		Alias:    "myAESProvider",
		KeyStore: keyStore,
		Key:      "publickey",
	}

	providers := make(map[string]CryptoProvider)
	providers["aes256"] = aesProvider

	_, err = EncryptJsonStruct(bytes, reflect.TypeOf(invalidCryptStruct), providers)
	if !IsCryptoErrorType(err, CryptoProviderMissingPrivateKey) {
		t.Fatalf("Expected missing private key error, was: %s", err)
	}
}

func TestMissingSigningKey(t *testing.T) {
	invalidCryptStruct := struct {
		CryptString string `cbcrypt:"rsa2048"`
	}{
		"something",
	}

	bytes, err := json.Marshal(invalidCryptStruct)
	if err != nil {
		t.Fatalf("Failed to marshal: %s", err)
	}

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaPrivateKey := marshalPKCS1PrivateKey(rsaKey)
	rsaPublicKey := marshalPKCS1PublicKey(&rsaKey.PublicKey)
	keyStore := &InsecureKeystore{
		Keys: map[string][]byte{
			"publickey":  rsaPublicKey,
			"signingkey": rsaPrivateKey,
		},
	}

	rsaProvider := &RsaCryptoProvider{
		Alias:     "myRSAProvider",
		KeyStore:  keyStore,
		PublicKey: "publickey",
	}

	providers := make(map[string]CryptoProvider)
	providers["rsa2048"] = rsaProvider

	_, err = EncryptJsonStruct(bytes, reflect.TypeOf(invalidCryptStruct), providers)
	if err == nil || !IsCryptoErrorType(err, CryptoProviderMissingSigningKey) {
		t.Fatalf("Expected missing signing key error, was: %s", err)
	}
}

func TestKeySizeError(t *testing.T) {
	invalidCryptStruct := struct {
		CryptString string `cbcrypt:"aes256"`
	}{
		"something",
	}

	bytes, err := json.Marshal(invalidCryptStruct)
	if err != nil {
		t.Fatalf("Failed to marshal: %s", err)
	}

	testKey, _ := hex.DecodeString("12345678901234561234567890123456123456789012345612345678901234561234")
	keyStore := &InsecureKeystore{
		Keys: map[string][]byte{
			"publickey": testKey,
			"hmackey":   testKey,
		},
	}

	aesProvider := &AesCryptoProvider{
		Alias:    "myAESProvider",
		KeyStore: keyStore,
		Key:      "publickey",
		HmacKey:  "hmackey",
	}

	providers := make(map[string]CryptoProvider)
	providers["aes256"] = aesProvider

	_, err = EncryptJsonStruct(bytes, reflect.TypeOf(invalidCryptStruct), providers)
	if err == nil || !IsCryptoErrorType(err, CryptoProviderKeySize) {
		t.Fatalf("Expected key size error, was: %v", err)
	}
}

func TestJsonTranscode(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaPrivateKey := marshalPKCS1PrivateKey(rsaKey)
	rsaPublicKey := marshalPKCS1PublicKey(&rsaKey.PublicKey)

	testKey, _ := hex.DecodeString("1234567890123456123456789012345612345678901234561234567890123456")
	keyStore := &InsecureKeystore{
		Keys: map[string][]byte{
			"somekey":    testKey,
			"hmackey":    testKey,
			"rsaprivkey": rsaPrivateKey,
			"rsapubkey":  rsaPublicKey,
		},
	}

	aesProvider := &AesCryptoProvider{
		Alias:    "myAESProvider",
		KeyStore: keyStore,
		Key:      "somekey",
		HmacKey:  "hmackey",
	}

	rsaProvider := &RsaCryptoProvider{
		Alias:      "myRSAProvider",
		KeyStore:   keyStore,
		PublicKey:  "rsapubkey",
		PrivateKey: "rsaprivkey",
	}

	testObj := testCryptStruct{
		NoCrypt:     "Hello",
		CryptString: "World",
		CryptNum:    1337,
		CryptoStruct: testSubStruct{
			TestString: "Franklyn",
			TestNum:    1448,
		},
	}

	coder := Transcoder{}
	coder.Register("myAESProvider", aesProvider)
	coder.Register("myRSAProvider", rsaProvider)

	encBytes, flags, err := coder.Encode(testObj)
	if err != nil {
		t.Fatalf("Failed to encode: %s", err)
	}

	decoded := testCryptStruct{}
	err = coder.Decode(encBytes, flags, &decoded)
	if err != nil {
		t.Fatalf("Failed to decode: %s", err)
	}

	if !reflect.DeepEqual(testObj, decoded) {
		t.Fatalf("Decoded document did not match original")
	}
}
