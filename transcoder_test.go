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

type PersonStreet struct {
	Firstline  string `json:"firstLine"`
	SecondLine string `json:"secondLine" encrypted:"one"`
}

type PersonAddress struct {
	HouseName  string                  `json:"houseName" encrypted:"one"`
	Street     []PersonStreet          `json:"streetName"`
	Attributes map[string]PetAttribute `json:"attributes" encrypted:"one"`
}

type PetAttribute struct {
	Action string `json:"action" encrypted:"one"`
	Extra  string `json:"extra"`
}

type Pet struct {
	Animal     string                  `json:"animal"`
	Attributes map[string]PetAttribute `json:"attributes" encrypted:"one"`
}

type Person struct {
	FirstName string          `json:"firstName"`
	LastName  string          `json:"lastName"`
	Password  string          `json:"password" encrypted:"one"`
	Addresses []PersonAddress `json:"address" encrypted:"one"`
	Pets      map[string]Pet  `json:"pets"`

	Phone string `json:"phone" encrypted:"one"`
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

	person := Person{
		FirstName: "Barry",
		LastName:  "Sheen",
		Password:  "bang!",
		Addresses: []PersonAddress{
			{
				HouseName: "my house",
				Street: []PersonStreet{
					{
						Firstline:  "my street",
						SecondLine: "my second line",
					},
				},
			},
			{
				HouseName: "my other house",
				Attributes: map[string]PetAttribute{
					"thing": {
						Action: "action",
						Extra:  "extra",
					},
				},
			},
		},
		Pets: map[string]Pet{
			"gary": {
				Animal: "dog",
				Attributes: map[string]PetAttribute{
					"tail": {
						Action: "wags",
					},
				},
			},
			"barry": {
				Animal: "cat",
				Attributes: map[string]PetAttribute{
					"claws": {
						Action: "scratch",
					},
				},
			},
		},
		Phone: "123456",
	}

	b, _, err := transcoder.Encode(person)
	if err != nil {
		t.Fatalf("Failed to encode data: %v", err)
	}

	var e map[string]interface{}
	err = json.Unmarshal(b, &e)
	if err != nil {
		t.Fatalf("Failed to unmarshal data: %v", err)
	}

	if len(e) != 6 {
		t.Fatalf("Encrypted object should have contained six keys: %#v", e)
	}

	enc, ok := e["encrypted$password"]
	if !ok {
		t.Fatalf("Encrypted object should have contained encrypted$password")
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

	if _, ok = e["encrypted$address"]; !ok {
		t.Fatalf("Encrypted object should have contained encrypted$address")
	}

	if _, ok = e["encrypted$phone"]; !ok {
		t.Fatalf("Encrypted object should have contained encrypted$phone")
	}

	if pets, ok := e["pets"]; ok {
		if barry, ok := pets.(map[string]interface{})["barry"]; ok {
			if _, ok = barry.(map[string]interface{})["encrypted$attributes"]; !ok {
				t.Fatalf("Encrypted barry should have contained encrypted$attributes")
			}
		} else {
			t.Fatalf("Pets object should have contained barry")
		}
		if gary, ok := pets.(map[string]interface{})["barry"]; ok {
			if _, ok = gary.(map[string]interface{})["encrypted$attributes"]; !ok {
				t.Fatalf("Encrypted gary should have contained encrypted$attributes")
			}
		} else {
			t.Fatalf("Pets object should have contained gary")
		}
	} else {
		t.Fatalf("Encrypted object should have contained pets")
	}

	var dataAfter Person
	err = transcoder.Decode(b, 0x2000000, &dataAfter)
	if err != nil {
		t.Fatalf("Failed to decode data: %v", err)
	}

	if !reflect.DeepEqual(dataAfter, person) {
		t.Fatalf("Expected result to be %+v but was %+v", person, dataAfter)
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

func TestTranscoderDocLevelArray(t *testing.T) {
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

	transcoder := NewTranscoder(nil, mgr)

	type doc struct {
		Maxim string `json:"maxim" encrypted:"one"`
	}

	data := []doc{
		{
			Maxim: "The enemy knows the system.",
		},
		{
			Maxim: "The enemy still knows the system.",
		},
	}

	b, _, err := transcoder.Encode(data)
	if err != nil {
		t.Fatalf("Failed to encode data: %v", err)
	}

	var e []interface{}
	err = json.Unmarshal(b, &e)
	if err != nil {
		t.Fatalf("Failed to unmarshal data: %v", err)
	}

	if len(e) != 2 {
		t.Fatalf("Expected encoded data to contain 2 elements: %#v", e)
	}

	expected := []interface{}{
		map[string]interface{}{
			"encrypted$maxim": map[string]interface{}{
				"alg":        "AEAD_AES_256_CBC_HMAC_SHA512",
				"ciphertext": "GvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4R5p5Deykuv2XLW4LcDvnOkmhuUSRbQ8QVEmbjq43XHdOm3ColJ6LzoaAtJihk=",
				"kid":        "test-key",
			},
		},
		map[string]interface{}{
			"encrypted$maxim": map[string]interface{}{
				"alg":        "AEAD_AES_256_CBC_HMAC_SHA512",
				"ciphertext": "GvOMLcK5b/3YZpQJI0G8BJwdjzItwo1W1TTvHpvBUpZpoMi21F73BdGIYGe08zLs/WQgiPfm3GOOfwzml3uBNPRLwonl5owrHJM64erP7ska1NwlvoIlQL66lpFLloPk",
				"kid":        "test-key",
			},
		},
	}

	if !reflect.DeepEqual(expected, e) {
		t.Fatalf("Value did not match expected, wanted: %#v but was %#v", expected, e)
	}

	var dataAfter []doc
	err = transcoder.Decode(b, 0x2000000, &dataAfter)
	if err != nil {
		t.Fatalf("Failed to decode data: %v", err)
	}

	if len(dataAfter) != 2 {
		t.Fatalf("Expected decoded data to contain 2 elements: %#v", dataAfter)
	}

	if dataAfter[0].Maxim != data[0].Maxim {
		t.Fatalf("Maxim did not match expected value")
	}

	if dataAfter[1].Maxim != data[1].Maxim {
		t.Fatalf("Maxim did not match expected value")
	}
}

func TestTranscoderDocLevelMap(t *testing.T) {
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

	transcoder := NewTranscoder(nil, mgr)

	type doc struct {
		Maxim string `json:"maxim" encrypted:"one"`
	}

	data := map[string]doc{
		"enemy1": {
			Maxim: "The enemy knows the system.",
		},
		"enemy2": {
			Maxim: "The enemy still knows the system.",
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

	if len(e) != 2 {
		t.Fatalf("Expected encoded data to contain 2 elements: %#v", e)
	}

	expected := map[string]interface{}{
		"enemy1": map[string]interface{}{
			"encrypted$maxim": map[string]interface{}{
				"alg":        "AEAD_AES_256_CBC_HMAC_SHA512",
				"ciphertext": "GvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4R5p5Deykuv2XLW4LcDvnOkmhuUSRbQ8QVEmbjq43XHdOm3ColJ6LzoaAtJihk=",
				"kid":        "test-key",
			},
		},
		"enemy2": map[string]interface{}{
			"encrypted$maxim": map[string]interface{}{
				"alg":        "AEAD_AES_256_CBC_HMAC_SHA512",
				"ciphertext": "GvOMLcK5b/3YZpQJI0G8BJwdjzItwo1W1TTvHpvBUpZpoMi21F73BdGIYGe08zLs/WQgiPfm3GOOfwzml3uBNPRLwonl5owrHJM64erP7ska1NwlvoIlQL66lpFLloPk",
				"kid":        "test-key",
			},
		},
	}

	if !reflect.DeepEqual(expected, e) {
		t.Fatalf("Value did not match expected, wanted: %#v but was %#v", expected, e)
	}

	var dataAfter map[string]doc
	err = transcoder.Decode(b, 0x2000000, &dataAfter)
	if err != nil {
		t.Fatalf("Failed to decode data: %v", err)
	}

	if len(dataAfter) != 2 {
		t.Fatalf("Expected decoded data to contain 2 elements: %#v", dataAfter)
	}

	if dataAfter["enemy1"].Maxim != data["enemy1"].Maxim {
		t.Fatalf("Maxim did not match expected value")
	}

	if dataAfter["enemy2"].Maxim != data["enemy2"].Maxim {
		t.Fatalf("Maxim did not match expected value")
	}
}
