/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */
package gocbfieldcrypt

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestTranscoder(t *testing.T) {
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
			"mysecondkey": {
				ID:    "mysecondkey",
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

	nonDefaultEncrypter := provider.EncrypterForKey("mysecondkey")
	nonDefaultEncrypter.iv = iv
	err = mgr.RegisterEncrypter("two", nonDefaultEncrypter)
	if err != nil {
		t.Fatalf("Failed to register encrypter: %v", err)
	}

	err = mgr.RegisterDecrypter(provider.Decrypter())
	if err != nil {
		t.Fatalf("Failed to register decrypter: %v", err)
	}

	transcoder := NewTranscoder(nil, mgr)

	type doc struct {
		Maxim string `json:"maxim" encrypted:"one"`
	}

	textVal := "The enemy knows the system."
	data := doc{
		Maxim: "The enemy knows the system.",
	}

	b, _, err := transcoder.Encode(data)
	if err != nil {
		t.Fatalf("Failed to encode data: %v", err)
	}

	var e map[string]interface{}
	err = json.Unmarshal(b, &e)
	if err != nil {
		t.Fatalf("Failed to unmarshal data: %v", err)
	}

	var dataAfter doc
	err = transcoder.Decode(b, 0x2000000, &dataAfter)
	if err != nil {
		t.Fatalf("Failed to decode data: %v", err)
	}

	if dataAfter.Maxim != textVal {
		t.Fatalf("Maxim did not match expected value")
	}
}

func TestTranscoderComplex(t *testing.T) {
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

	err = mgr.DefaultEncrypter(defaultEncrypter)
	if err != nil {
		t.Fatalf("Failed to register default encrypter: %v", err)
	}

	err = mgr.RegisterDecrypter(provider.Decrypter())
	if err != nil {
		t.Fatalf("Failed to register decrypter: %v", err)
	}

	transcoder := NewTranscoder(nil, mgr)

	type str struct {
		Meh string `json:"str"`
	}

	type inner struct {
		Arr []string          `json:"arr" encrypted:""`
		Map map[string]string `json:"map" encrypted:""`
		Str str               `json:"str" encrypted:"one"`
	}

	type outer struct {
		Inner  inner  `json:"inner"`
		String string `json:"string" encrypted:"one"`
		Number int    `json:"number" encrypted:""`
	}

	type doc struct {
		Outer outer `json:"outer" encrypted:"one"`
	}

	textVal := "The enemy knows the system."
	data := doc{
		Outer: outer{
			Inner: inner{
				Arr: []string{textVal},
				Map: map[string]string{
					"maxim": textVal,
				},
				Str: str{
					Meh: "system",
				},
			},
			String: "Get out of my system.",
			Number: 111,
		},
	}

	b, _, err := transcoder.Encode(data)
	if err != nil {
		t.Fatalf("Failed to encode data: %v", err)
	}

	var e map[string]interface{}
	err = json.Unmarshal(b, &e)
	if err != nil {
		t.Fatalf("Failed to unmarshal data: %v", err)
	}

	if len(e) != 1 {
		t.Fatalf("Encrypted object should have contained only one key")
	}

	enc, ok := e["encrypted$outer"]
	if !ok {
		t.Fatalf("Encrypted object should have contained encrypted$outer")
	}

	encAssert, ok := enc.(map[string]interface{})
	if !ok {
		t.Fatalf("Encrypted object was not map, was: %v", enc)
	}

	alg, ok := encAssert["alg"]
	if !ok {
		t.Fatalf("Expected encrypted field to contain alg")
	}

	if alg != "AEAD_AES_256_CBC_HMAC_SHA512" {
		t.Fatalf("Expected algorithm to be AEAD_AES_256_CBC_HMAC_SHA512 but was %s", alg)
	}

	resKey := encAssert["kid"]
	if !ok {
		t.Fatalf("Expected encrypted field to contain kid")
	}

	if resKey != "test-key" {
		t.Fatalf("Result kid should have been mytestkey but was %s", resKey)
	}

	var dataAfter doc
	err = transcoder.Decode(b, 0x2000000, &dataAfter)
	if err != nil {
		t.Fatalf("Failed to decode data: %v", err)
	}

	if !reflect.DeepEqual(dataAfter, data) {
		t.Fatalf("Expected result to be %+v but was %+v", data, dataAfter)
	}
}

func TestTranscoderLegacyAes(t *testing.T) {
	keyStore := &InsecureKeyring{
		keys: map[string]Key{
			"mypublickey": {
				ID:    "mypublickey",
				Bytes: []byte("!mysecretkey#9^5usdk39d&dlf)03sL"),
			},
			"myhmackey": {
				ID:    "myhmackey",
				Bytes: []byte("myauthpassword"),
			},
		},
	}

	provider := NewLegacyAes256CryptoDecrypter(keyStore, "mypublickey", "myhmackey")

	mgr := NewDefaultCryptoManager(&DefaultCryptoManagerOptions{
		EncryptedFieldPrefix: "__crypt_",
	})

	err := mgr.RegisterDecrypter(provider)
	if err != nil {
		t.Fatalf("Failed to register decrypter: %v", err)
	}

	transcoder := NewTranscoder(nil, mgr)

	type message struct {
		Message string `json:"message" encrypted:"myaesprovider"`
	}
	testDoc := message{
		Message: "The old grey goose jumped over the wrickety gate.",
	}

	testEncDoc := map[string]interface{}{
		"__crypt_message": map[string]string{
			"alg":        "AES-256-HMAC-SHA256",
			"kid":        "mypublickey",
			"iv":         "Cfq84/46Qjet3EEQ1HUwSg==",
			"ciphertext": "sR6AFEIGWS5Fy9QObNOhbCgfg3vXH4NHVRK1qkhKLQqjkByg2n69lot89qFEJuBsVNTXR77PZR6RjN4h4M9evg==",
			"sig":        "rT89aCj1WosYjWHHu0mf92S195vYnEGA/reDnYelQsM=",
		},
	}

	b, err := json.Marshal(testEncDoc)
	if err != nil {
		t.Fatalf("Failed to marshal data: %v", err)
	}

	var dataAfter message
	err = transcoder.Decode(b, 0x2000000, &dataAfter)
	if err != nil {
		t.Fatalf("Failed to decode data: %v", err)
	}

	if dataAfter.Message != testDoc.Message {
		t.Fatalf("Message %s did not match expected value %s", dataAfter.Message, testDoc.Message)
	}
}
