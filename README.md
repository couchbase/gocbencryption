# Couchbase Field Level Encryption for GO SDK
Field Level based Encryption library for the Go Couchbase SDK. Encrypted fields are protected in transit and at rest. The library provides functionality for encryption and decryption.

## Getting Started ##
```
go get github.com/couchbase/gocbencryption/v2
```

The Couchbase Go Field Level Encryption (FLE) library uses struct tags to specify which field(s) to apply encryption to and what provider to use.
The struct tag key is `encrypted` and the value is of the form `"encrypter-alias"`. 
Here’s an example struct definition:

```
type PersonAddress struct {
	HouseName  string `json:"houseName" encrypted:"one"`
	StreetName string `json:"streetName"`
}

type Person struct {
	FirstName string        `json:"firstName"`
	LastName  string        `json:"lastName"`
	Password  string        `json:"password" encrypted:"one"`
	Address   PersonAddress `json:"address" encrypted:"two"`

	Phone string `json:"phone" encrypted:"two"`
}
```
You need to create a Key Store, a CryptoManager, (at least one) Provider and a Transcoder.

* The provider provides encrypters and decrypters.
* The transcoder is responsible for calling into the manager for each encrypted field during operations.
* The manager is responsible for using providers to encrypt and decrypt fields.
* You can register multiple (uniquely aliased) encryptors with a manager.
* You can also register multiple decryptors with a manager, although only per algorithm.

After installing the dependency you need to set up your Key Store, Manager, Provider and Transcoder (note that the key id passed to an encrypter matches the struct tags):

```
// Create our keys.
keyB := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x3f, 0x3f, 0x3f, 0x3f, 0x3d, 0x3e, 0x3f,
}
key1 := gocbfieldcrypt.Key{
    ID:    "mykey",
    Bytes: keyB,
}
key2 := gocbfieldcrypt.Key{
    ID:    "myotherkey",
    Bytes: keyB,
}

// Create the keyring and add both of these keys.
// You should use a secure keyring in your application.
keyring := gocbfieldcrypt.NewInsecureKeyring()
keyring.Add(key)
keyring.Add(key2)


// Create a provider.
// AES-256 authenticated with HMAC SHA-512. Requires a 64-byte key.
provider := gocbfieldcrypt.NewAeadAes256CbcHmacSha512Provider(keyring)

// Create the manager and add the providers.
mgr := gocbfieldcrypt.NewDefaultCryptoManager(nil)

// We need to create and then register encrypters.
// The keyID here is used by the encrypter to lookup the key from the store when encrypting a document.
// The key.ID returned from the store at encryption time is written into the data for the field to be encrypted.
// The key ID that was written is then used on the decrypt side to find the corresponding key from the store.
keyOneEncrypter := provider.EncrypterForKey(key1.ID)

// We register the providers for both encryption and decryption.
// The alias used here is the value which corresponds to the "encrypted" field annotation.
err := mgr.RegisterEncrypter("one", keyOneEncrypter)
if err != nil {
    panic(err)
}

err = mgr.RegisterEncrypter("two", provider.EncrypterForKey(key2.ID))
if err != nil {
    panic(err)
}

// We don't need to add a default encryptor but if we do then any fields with an
// empty encrypted tag will use this encryptor.
err = mgr.DefaultEncrypter(keyOneEncrypter)
if err != nil {
    panic(err)
}

// We only set one decrypter per algorithm.
// The crypto manager will work out which decrypter to use based on the alg field embedded in the field data.
// The decrypter will use the key embedded in the field data to determine which key to fetch from the key store for decryption.
err = mgr.RegisterDecrypter(provider.Decrypter())
if err != nil {
    panic(err)
}

// Create our transcoder, not setting a base transcoder will cause it to fallback to the
// SDK JSON transcoder.
transcoder := gocbfieldcrypt.NewTranscoder(nil, mgr)
```

Next you need to create a configuration to connect to your cluster and set your transcoder on the cluster options:

```
cluster, err := gocb.Connect("localhost", gocb.ClusterOptions{
    Username:   "username",
    Password:   "password",
    Transcoder: transcoder,
})
if err != nil {
    panic(err)
}

b := cluster.Bucket("default")
col := b.DefaultCollection()
```

You can then perform KV operations and your data will be encrypted/decrypted automatically:
```
person := Person{
    FirstName: "Barry",
    LastName:  "Sheen",
    Password:  "bang!",
    Address: PersonAddress{
        HouseName:  "my house",
        StreetName: "my street",
    },
    Phone: "123456",
}

_, err = col.Upsert("p1", person, nil)
if err != nil {
    panic(err)
}

res, err := col.Get("p1", nil)
if err != nil {
    panic(err)
}

// We can get the content like this in order to not decrypt any of the data.
// If we didn't have the full set of keys then we could use this to manually decrypt specific fields.
var resData map[string]interface{}
err = res.Content(&resData)
if err != nil {
    panic(err)
}

fmt.Printf("%+v\n", resData)

getData, err := col.Get("p1", nil)
if err != nil {
    panic(err)
}

// If we fetch the data into a type which is annotated then the fields will automatically be decrypted using the registered
// decrypters and keys.
var getPerson Person
err = res.Content(&getPerson)
if err != nil {
    panic(err)
}

fmt.Printf("%+v", person)
```

### Limitations

Due to how the FLE library works `interface{}` fields are not currently supported.
If the `interface{}` field itself is being encrypted then the library will work, e.g.:

```
type Person struct {
    FirstName string        `json:"firstName"`
    LastName  interface{}   `json:"lastName"`
}
```

However, if the `interface{}` field is a complex object, or an array of objects, then any nested annotated fields will not be encrypted at the field level.
