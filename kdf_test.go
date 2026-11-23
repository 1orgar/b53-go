package b53

import (
	"encoding/hex"
	"errors"
	"testing"
)

func TestDefaultScryptConstants(t *testing.T) {
	if DefaultScryptN != 1<<15 {
		t.Fatalf("DefaultScryptN = %d, want %d", DefaultScryptN, 1<<15)
	}
	if DefaultScryptR != 8 {
		t.Fatalf("DefaultScryptR = %d, want 8", DefaultScryptR)
	}
	if DefaultScryptP != 1 {
		t.Fatalf("DefaultScryptP = %d, want 1", DefaultScryptP)
	}
	if DefaultScryptMaxMem != 128*1024*1024 {
		t.Fatalf("DefaultScryptMaxMem = %d, want %d", DefaultScryptMaxMem, 128*1024*1024)
	}
}

func TestScryptRFC7914Vectors(t *testing.T) {
	// Official RFC 7914 Section 12 test vectors (first 3 vectors).
	vectors := []struct {
		password string
		salt     string
		n, r, p  int
		wantHex  string
	}{
		{
			password: "",
			salt:     "",
			n:        16,
			r:        1,
			p:        1,
			wantHex:  "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
		},
		{
			password: "password",
			salt:     "NaCl",
			n:        1024,
			r:        8,
			p:        16,
			wantHex:  "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
		},
		{
			password: "pleaseletmein",
			salt:     "SodiumChloride",
			n:        16384,
			r:        8,
			p:        1,
			wantHex:  "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
		},
	}

	for i, tc := range vectors {
		got, err := scryptKey([]byte(tc.password), []byte(tc.salt), tc.n, tc.r, tc.p, 0, 64)
		if err != nil {
			t.Fatalf("RFC 7914 vector %d failed: %v", i, err)
		}
		if gotHex := hex.EncodeToString(got); gotHex != tc.wantHex {
			t.Fatalf("RFC 7914 vector %d mismatch:\n got: %s\nwant: %s", i, gotHex, tc.wantHex)
		}
	}
}

func TestDeriveSaltMatchesPythonAndRoundtrips(t *testing.T) {
	const password = "correct-horse-battery-staple"
	saltHex, err := DeriveSalt(password)
	if err != nil {
		t.Fatalf("DeriveSalt failed: %v", err)
	}
	if len(saltHex) != 64 {
		t.Fatalf("len(saltHex) = %d, want 64", len(saltHex))
	}

	// Exact golden value produced by Python b53.derive_salt("correct-horse-battery-staple").
	const wantDefault = "6327d60cb921a0affce791169845c75c3409185a8231d01584132e0286fdce5d"
	if saltHex != wantDefault {
		t.Fatalf("DeriveSalt default mismatch:\n got: %s\nwant: %s", saltHex, wantDefault)
	}

	bits := []bool{true, false, true, true, false, false, true}
	encoded, err := Encrypt(bits, saltHex)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := Decrypt(encoded, saltHex)
	if err != nil || !equalBools(dec, bits) {
		t.Fatalf("Decrypt failed: %v", err)
	}

	many := make([]bool, 42)
	for i := range many {
		many[i] = i%2 == 0
	}
	doubles, err := Serialize(many, saltHex)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Deserialize(doubles, saltHex)
	if err != nil || !equalBools(restored, many) {
		t.Fatalf("Deserialize failed: %v", err)
	}
}

func TestDeriveSaltContextAndWhitespaceSensitivity(t *testing.T) {
	fast := WithScryptParams(16, 1, 1)

	k1, err := DeriveSalt("secret", fast)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveSalt(" secret", fast)
	if err != nil {
		t.Fatal(err)
	}
	k3, err := DeriveSalt("secret", WithContext("user:1"), fast)
	if err != nil {
		t.Fatal(err)
	}
	k4, err := DeriveSalt([]byte("secret"), WithContext([]byte("user:1")), fast)
	if err != nil {
		t.Fatal(err)
	}
	k5, err := DeriveSalt("secret", WithContext("user:2"), fast)
	if err != nil {
		t.Fatal(err)
	}

	if k1 == k2 {
		t.Fatal("leading whitespace in password was unexpectedly trimmed")
	}
	if k1 == k3 {
		t.Fatal("context did not alter derived salt")
	}
	if k3 != k4 {
		t.Fatal("string and []byte password/context produced different keys")
	}
	if k3 == k5 {
		t.Fatal("different contexts produced identical keys")
	}

	k16, err := DeriveSalt("secret", WithContext("user:1"), WithNumBytes(16), fast)
	if err != nil {
		t.Fatal(err)
	}
	if k16 != "da2e9dc81cd4f66aaf660c1dd2b3de9d" {
		t.Fatalf("k16 mismatch: got %s, want Python golden da2e9dc81cd4f66aaf660c1dd2b3de9d", k16)
	}
}

func TestNewCipherFromPasswordInteroperatesWithDeriveSalt(t *testing.T) {
	opts := []DeriveOption{WithContext("tenant-a"), WithScryptParams(16, 1, 1)}
	salt, err := DeriveSalt("my-password", opts...)
	if err != nil {
		t.Fatal(err)
	}
	if salt != "c0ecc4f8084ce34736771e417c5ee34f85f2b2ff51b794c43dc9e4c73765b52a" {
		t.Fatalf("DeriveSalt golden mismatch: got %s", salt)
	}

	cipher, err := NewCipherFromPassword("my-password", opts...)
	if err != nil {
		t.Fatal(err)
	}

	bits := make([]bool, 35)
	for i := range bits {
		bits[i] = i%3 == 0
	}

	doubles, err := cipher.Serialize(bits)
	if err != nil {
		t.Fatal(err)
	}
	dec1, err := Deserialize(doubles, salt)
	if err != nil || !equalBools(dec1, bits) {
		t.Fatalf("Deserialize mismatch: %v", err)
	}

	doubles2, err := Serialize(bits, salt)
	if err != nil {
		t.Fatal(err)
	}
	dec2, err := cipher.Deserialize(doubles2)
	if err != nil || !equalBools(dec2, bits) {
		t.Fatalf("cipher.Deserialize mismatch: %v", err)
	}
}

func TestDeriveSaltValidation(t *testing.T) {
	if _, err := DeriveSalt(""); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("DeriveSalt(\"\") err = %v, want ErrEmptyPassword", err)
	}
	if _, err := DeriveSalt([]byte{}); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("DeriveSalt([]byte{}) err = %v, want ErrEmptyPassword", err)
	}
	if _, err := DeriveSalt([]byte(nil)); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("DeriveSalt(nil) err = %v, want ErrEmptyPassword", err)
	}

	if _, err := DeriveSalt("pw", WithContext("")); !errors.Is(err, ErrEmptyContext) {
		t.Fatalf("WithContext(\"\") err = %v, want ErrEmptyContext", err)
	}
	if _, err := DeriveSalt("pw", WithContext([]byte{})); !errors.Is(err, ErrEmptyContext) {
		t.Fatalf("WithContext([]byte{}) err = %v, want ErrEmptyContext", err)
	}

	if _, err := DeriveSalt("pw", WithNumBytes(15)); !errors.Is(err, ErrSaltTooShort) {
		t.Fatalf("WithNumBytes(15) err = %v, want ErrSaltTooShort", err)
	}

	for _, badN := range []int{0, 1, 3, 12, -16} {
		if _, err := DeriveSalt("pw", WithScryptParams(badN, 1, 1)); !errors.Is(err, ErrInvalidScryptParam) {
			t.Fatalf("bad n=%d err = %v, want ErrInvalidScryptParam", badN, err)
		}
	}
	if _, err := DeriveSalt("pw", WithScryptParams(16, 0, 1)); !errors.Is(err, ErrInvalidScryptParam) {
		t.Fatalf("r=0 err = %v, want ErrInvalidScryptParam", err)
	}
	if _, err := DeriveSalt("pw", WithScryptParams(16, 1, 0)); !errors.Is(err, ErrInvalidScryptParam) {
		t.Fatalf("p=0 err = %v, want ErrInvalidScryptParam", err)
	}
	if _, err := DeriveSalt("pw", WithScryptParams(16, 1, 1), WithScryptMaxMem(-1)); !errors.Is(err, ErrInvalidScryptParam) {
		t.Fatalf("maxMem=-1 err = %v, want ErrInvalidScryptParam", err)
	}
	if _, err := DeriveSalt("pw", WithScryptParams(16, 1, 1), WithScryptMaxMem(1024)); !errors.Is(err, ErrScryptMemoryLimit) {
		t.Fatalf("maxMem=1024 err = %v, want ErrScryptMemoryLimit", err)
	}
}
