package b53a_test

import (
	"fmt"
	"log"

	"github.com/1orgar/b53-go"
	"github.com/1orgar/b53-go/b53a"
)

func ExampleSealSession() {
	bob, err := b53a.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	enc, capsule, err := b53a.SealSession(bob.PublicKey, b53a.WithContext("table:flags"))
	if err != nil {
		log.Fatal(err)
	}
	d, err := enc.Encrypt([]bool{true, false, true, true})
	if err != nil {
		log.Fatal(err)
	}

	dec, err := b53a.OpenSession(capsule, bob.PrivateKey, b53a.WithContext("table:flags"))
	if err != nil {
		log.Fatal(err)
	}
	restored, err := dec.Decrypt(d)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(b53.FormatBits(restored))
	// Output:
	// 1011
}

func ExampleEncrypt() {
	alice, err := b53a.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	bob, err := b53a.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	encoded, err := b53a.Encrypt([]bool{true, false, true}, alice.PrivateKey, bob.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	restored, err := b53a.Decrypt(encoded, bob.PrivateKey, alice.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(b53.FormatBits(restored))
	// Output:
	// 101
}
