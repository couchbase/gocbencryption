# Couchbase Field Level Encryption for GO SDK
Field Level based Encryption library for the Go Couchbase SDK. Encrypted fields are protected in transit and at rest. The library provides functionality for encryption and decryption.

## Getting Started ##
```
go get github.com/couchbase/gocbencryption
```

The Couchbase Go Field Level Encryption (FLE) library uses struct tags to specify which field(s) to apply encryption to and what provider to use. The struct tag key is `cbcrypt` and the value is of the form `"provider"`. Here’s an example struct definition:

```
type PersonAddress struct {
    HouseName    string `json:"houseName"`
    StreetName   string `json:"streetName"`
}

type Person struct {
    FirstName string        `json:"firstName"`
    LastName  string        `json:"lastName"`
    Password  string        `json:"password" cbcrypt:"myAESProvider"`
    Address   PersonAddress `json:"address" cbcrypt:"myAESProvider"`
}
```
You need to create a Key Store, Provider and a Transcoder. The provider is used to perform encyption/decryption and the transcoder is responsible for using the provider  during operations. You can register multiple (uniquely aliased) providers with a transcoder. After installing the dependency you need to set up your Key Store, Provider and Transcoder (note that the alias name of the provider matches the struct tags):

```
keyStore := &gocbfieldcrypt.InsecureKeystore{
    Keys: map[string][]byte{
       "mypublickey": []byte("!mysecretkey#9^5usdk39d&dlf)03sL"),
       "myhmackey":   []byte("myauthpassword"),
    },
}

aesProvider := &gocbfieldcrypt.AesCryptoProvider{
	Alias:    "myAESProvider",
	KeyStore: keyStore,
	Key:      "mypublickey",
	HmacKey:  "myhmackey",
}

coder := gocbfieldcrypt.Transcoder{}
coder.Register("myAESProvider", aesProvider)
```

Next you need to create a configuration to connect to your cluster and set your transcoder on the bucket:

```
cluster, _ := gocb.Connect("…")
cluster.Authenticate(…)
bucket, _ := cluster.openBucket("…", "")
bucket.SetTranscoder(&coder)
```

You can then perform KV operations as usual and your data will be encrypted/decrypted automatically:
```
person := Person{
    FirstName: "Barry",
    LastName:  "Sheen",
    Password:  "bang!",
    Address: PersonAddress{
        HouseName:  "my house",
        StreetName: "my street",
    },
}

bucket.Upsert("p1", person, 0)
```
