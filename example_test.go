package b53_test

import (
	"fmt"
	"log"

	"github.com/1orgar/b53-go"
)

func ExampleEncrypt() {
	const salt = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	bits := []bool{true, false, true, true, false, false, true, false, true, true}

	encoded, err := b53.Encrypt(bits, salt)
	if err != nil {
		log.Fatal(err)
	}
	restored, err := b53.Decrypt(encoded, salt)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(b53.FormatBits(restored))
	// Output:
	// 1011001011
}

func ExampleNewCipher() {
	cipher, err := b53.NewCipher("my-secret-passphrase")
	if err != nil {
		log.Fatal(err)
	}

	encoded, err := cipher.EncryptString("1011001011")
	if err != nil {
		log.Fatal(err)
	}
	decoded, err := cipher.DecryptString(encoded)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(decoded)
	// Output:
	// 1011001011
}

func ExampleSerialize() {
	const salt = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	bits := make([]bool, 45)
	for i := range bits {
		bits[i] = i%3 == 0
	}

	doubles, err := b53.Serialize(bits, salt)
	if err != nil {
		log.Fatal(err)
	}
	restored, err := b53.Deserialize(doubles, salt)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(doubles), b53.FormatBits(restored) == b53.FormatBits(bits))
	// Output:
	// 5 true
}

func ExampleDeriveSalt() {
	salt, err := b53.DeriveSalt("my-passphrase", b53.WithContext("tenant-a"), b53.WithScryptParams(16, 1, 1))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(salt))
	// Output:
	// 64
}
