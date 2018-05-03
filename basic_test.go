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
	CryptString  string        `cbcrypt:"aes256,somekey,hmackey"`
	CryptNum     int           `cbcrypt:"aes256,somekey,hmackey"`
	CryptoStruct testSubStruct `cbcrypt:"rsa2048,rsapubkey,rsaprivkey"`
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

	encBytes, err := EncryptJsonStruct(bytes, reflect.TypeOf(testObj), keyStore)
	if err != nil {
		t.Fatalf("Failed to encrypt: %s", err)
	}

	decBytes, err := DecryptJsonStruct(encBytes, reflect.TypeOf(testObj), keyStore)
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
	Message string `cbcrypt:"aes256,mypublickey,myhmackey" json:"message"`
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

	decData, err := DecryptJsonStruct(encDataBytes, reflect.TypeOf(testDoc), keyStore)
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
