package b53a

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/1orgar/b53-go"
)

func equalBools(a, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestKeyPairGenerationAndRedaction(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if len(kp.PrivateKey) != 64 || len(kp.PublicKey) != 64 {
		t.Fatalf("unexpected key lengths: priv=%d pub=%d", len(kp.PrivateKey), len(kp.PublicKey))
	}

	pubFromHex, err := PublicKeyFromPrivate(kp.PrivateKey)
	if err != nil || pubFromHex != kp.PublicKey {
		t.Fatalf("PublicKeyFromPrivate(hex) = (%q, %v), want %q", pubFromHex, err, kp.PublicKey)
	}

	rawPriv, err := hex.DecodeString(kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	pubFromBytes, err := PublicKeyFromPrivate(rawPriv)
	if err != nil || pubFromBytes != kp.PublicKey {
		t.Fatalf("PublicKeyFromPrivate(bytes) = (%q, %v), want %q", pubFromBytes, err, kp.PublicKey)
	}

	// String() and GoString() must never leak PrivateKey.
	s := kp.String()
	gs := fmt.Sprintf("%#v", kp)
	if strings.Contains(s, kp.PrivateKey) || strings.Contains(gs, kp.PrivateKey) {
		t.Fatal("private key leaked in String()/GoString()")
	}
	if !strings.Contains(s, kp.PublicKey) || !strings.Contains(s, "<redacted>") {
		t.Fatalf("unexpected String(): %q", s)
	}
	if !strings.Contains(gs, kp.PublicKey) || !strings.Contains(gs, "<redacted>") {
		t.Fatalf("unexpected GoString(): %q", gs)
	}
}

func TestSealedSessionRoundtripWithoutKeyInOutputArray(t *testing.T) {
	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	eve, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	encCipher, capsule, err := SealSession(bob.PublicKey, WithContext("table:users"))
	if err != nil {
		t.Fatalf("SealSession failed: %v", err)
	}
	if len(capsule) != 64 {
		t.Fatalf("capsule length = %d, want 64", len(capsule))
	}
	if _, err := hex.DecodeString(capsule); err != nil {
		t.Fatalf("capsule is not valid hex: %v", err)
	}

	row1 := []bool{true, false, true, true}
	row2 := make([]bool, 50)
	for i := range row2 {
		row2[i] = i%2 == 0
	}

	d1, err := encCipher.Encrypt(row1)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := encCipher.Encrypt(row2)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []float64{d1, d2} {
		if d < 0.0 || d >= 1.0 || math.Trunc(math.Ldexp(d, b53.MantissaBits)) != math.Ldexp(d, b53.MantissaBits) {
			t.Fatalf("encrypted value %v not on 2^-53 grid", d)
		}
	}

	decCipher, err := OpenSession(capsule, bob.PrivateKey, WithContext("table:users"))
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}
	if got1, err := decCipher.Decrypt(d1); err != nil || !equalBools(got1, row1) {
		t.Fatalf("Decrypt(d1) = (%v, %v), want %v", got1, err, row1)
	}
	if got2, err := decCipher.Decrypt(d2); err != nil || !equalBools(got2, row2) {
		t.Fatalf("Decrypt(d2) = (%v, %v), want %v", got2, err, row2)
	}

	// SerializeSealed preserves exact fixed chunk count (no ephemeral key stuffed in doubles).
	many := make([]bool, 42)
	for i := range many {
		many[i] = i%3 == 0
	}
	doubles, serCapsule, err := SerializeSealed(many, bob.PublicKey, WithMinSize(10))
	if err != nil {
		t.Fatalf("SerializeSealed failed: %v", err)
	}
	if len(doubles) != (42/10)+1 {
		t.Fatalf("len(doubles) = %d, want %d", len(doubles), (42/10)+1)
	}
	if serCapsule == capsule {
		t.Fatal("expected distinct ephemeral capsule per SerializeSealed call")
	}
	restoredMany, err := DeserializeSealed(doubles, serCapsule, bob.PrivateKey)
	if err != nil || !equalBools(restoredMany, many) {
		t.Fatalf("DeserializeSealed failed: %v", err)
	}

	// Single-shot EncryptSealed / DecryptSealed.
	val, oneCap, err := EncryptSealed([]bool{true, false, false, true}, bob.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	gotOne, err := DecryptSealed(val, oneCap, bob.PrivateKey)
	if err != nil || !equalBools(gotOne, []bool{true, false, false, true}) {
		t.Fatalf("DecryptSealed failed: %v", err)
	}

	// Wrong private key or wrong context fails recovery.
	wrongCipher, err := OpenSession(capsule, eve.PrivateKey, WithContext("table:users"))
	if err != nil {
		t.Fatal(err)
	}
	if gotWrong, _ := wrongCipher.Decrypt(d2); equalBools(gotWrong, row2) {
		t.Fatal("wrong private key unexpectedly decrypted row2")
	}

	wrongCtx, err := OpenSession(capsule, bob.PrivateKey, WithContext("table:other"))
	if err != nil {
		t.Fatal(err)
	}
	if gotWrongCtx, _ := wrongCtx.Decrypt(d2); equalBools(gotWrongCtx, row2) {
		t.Fatal("wrong context unexpectedly decrypted row2")
	}
}

func TestPairwiseAsymmetricEncryptAndSerialize(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	eve, _ := GenerateKeyPair()

	sAB, err := DeriveSharedSalt(alice.PrivateKey, bob.PublicKey, WithContext("chan-1"))
	if err != nil {
		t.Fatal(err)
	}
	sBA, err := DeriveSharedSalt(bob.PrivateKey, alice.PublicKey, WithContext("chan-1"))
	if err != nil {
		t.Fatal(err)
	}
	if sAB != sBA {
		t.Fatalf("shared salt mismatch: AB=%s BA=%s", sAB, sBA)
	}
	if sOther, err := DeriveSharedSalt(alice.PrivateKey, bob.PublicKey, WithContext("chan-2")); err != nil || sOther == sAB {
		t.Fatal("different context did not change shared salt")
	}
	if sEve, err := DeriveSharedSalt(eve.PrivateKey, bob.PublicKey, WithContext("chan-1")); err != nil || sEve == sAB {
		t.Fatal("different peer did not change shared salt")
	}

	bits := []bool{true, false, true, true, false, true}
	encoded, err := Encrypt(bits, alice.PrivateKey, bob.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := Decrypt(encoded, bob.PrivateKey, alice.PublicKey)
	if err != nil || !equalBools(dec, bits) {
		t.Fatalf("Decrypt failed: %v", err)
	}

	many := make([]bool, 77)
	for i := range many {
		many[i] = i%5 < 2
	}
	doubles, err := Serialize(many, alice.PrivateKey, bob.PublicKey, WithMinSize(10), WithContext("ctx"))
	if err != nil {
		t.Fatal(err)
	}
	if len(doubles) != (77/10)+1 {
		t.Fatalf("len(doubles) = %d, want %d", len(doubles), (77/10)+1)
	}
	restored, err := Deserialize(doubles, bob.PrivateKey, alice.PublicKey, WithContext("ctx"))
	if err != nil || !equalBools(restored, many) {
		t.Fatalf("Deserialize failed: %v", err)
	}
}

func TestNativeECDHKeysAndNewCipher(t *testing.T) {
	type customKeyHex string
	type customKeyBytes []byte

	alicePriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	aliceCipher, err := NewCipher(alicePriv, bobPriv.PublicKey(), WithContext([]byte("row:9")))
	if err != nil {
		t.Fatal(err)
	}
	bobCipher, err := NewCipher(bobPriv, alicePriv.PublicKey(), WithContext("row:9"))
	if err != nil {
		t.Fatal(err)
	}
	if aliceCipher.KeyLen() != X25519KeyBytes {
		t.Fatalf("KeyLen = %d, want %d", aliceCipher.KeyLen(), X25519KeyBytes)
	}

	payload := []bool{true, true, false, true, false, false, true}
	x, err := aliceCipher.Encrypt(payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err := bobCipher.Decrypt(x)
	if err != nil || !equalBools(got, payload) {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify derived string/bytes key types work seamlessly.
	aliceHex := customKeyHex(hex.EncodeToString(alicePriv.Bytes()))
	bobPubBytes := customKeyBytes(bobPriv.PublicKey().Bytes())
	s1, err := DeriveSharedSalt(aliceHex, bobPubBytes, WithContext("row:9"))
	if err != nil {
		t.Fatal(err)
	}
	s2, err := DeriveSharedSalt(alicePriv, bobPriv.PublicKey(), WithContext("row:9"))
	if err != nil || s1 != s2 {
		t.Fatalf("derived types mismatch: s1=%s s2=%s err=%v", s1, s2, err)
	}
}

func TestKeyValidationAndLowOrderPointRejection(t *testing.T) {
	kp, _ := GenerateKeyPair()

	zeroHex := strings.Repeat("00", 32)
	if _, _, err := SealSession(zeroHex); !errors.Is(err, ErrLowOrderPoint) && !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("SealSession(zeroHex) err = %v", err)
	}
	if _, err := DeriveSharedSalt(kp.PrivateKey, make([]byte, 32)); !errors.Is(err, ErrLowOrderPoint) && !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("DeriveSharedSalt(zeroBytes) err = %v", err)
	}

	for _, badKey := range []string{"", "   ", "zzzz", strings.Repeat("ab", 31), strings.Repeat("ab", 33)} {
		if _, _, err := SealSession(badKey); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("SealSession(%q) err = %v, want ErrInvalidKey", badKey, err)
		}
		if _, err := PublicKeyFromPrivate(badKey); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("PublicKeyFromPrivate(%q) err = %v, want ErrInvalidKey", badKey, err)
		}
	}

	if _, _, err := SealSession(kp.PublicKey, WithContext("")); !errors.Is(err, ErrEmptyContext) {
		t.Fatalf("WithContext(\"\") err = %v, want ErrEmptyContext", err)
	}
	if _, _, err := SealSession(kp.PublicKey, WithContext([]byte{})); !errors.Is(err, ErrEmptyContext) {
		t.Fatalf("WithContext([]byte{}) err = %v, want ErrEmptyContext", err)
	}
	if _, _, err := SerializeSealed([]bool{true}, kp.PublicKey, WithMinSize(1)); !errors.Is(err, b53.ErrInvalidMinSize) {
		t.Fatalf("WithMinSize(1) err = %v, want b53.ErrInvalidMinSize", err)
	}

	var nilPriv *ecdh.PrivateKey
	var nilPub *ecdh.PublicKey
	if _, err := PublicKeyFromPrivate(nilPriv); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("nil private key err = %v, want ErrInvalidKey", err)
	}
	if _, _, err := SealSession(nilPub); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("nil public key err = %v, want ErrInvalidKey", err)
	}

	p256Priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublicKeyFromPrivate(p256Priv); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("P256 private key err = %v, want ErrInvalidKey", err)
	}
	if _, _, err := SealSession(p256Priv.PublicKey()); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("P256 public key err = %v, want ErrInvalidKey", err)
	}
}

func TestPythonB53aGoldenVectors(t *testing.T) {
	const (
		alicePriv = "90a39e6e954831897c213b4314d390161c8df7b2e357f21580b3a4a7716cc57d"
		alicePub  = "4cae00984a7e12c0466c56e84c2b44a32c963759e4268a91e7c6ade49197bb76"
		bobPriv   = "4034941cb06889d8011a5f4cc60013061c201d7ecedfd6a22ee69cc7a7f7db72"
		bobPub    = "a862bcc58f7c4eda80f7f4ce9e5dddd256fe49ca37b40ad0945f0d7c6c37b70d"

		wantSharedCtx   = "e1111e66027e0077507b1933b7aa8c38ac361cf9e485993ed562fdc1ed8377be"
		wantSharedNoCtx = "b9d395f0e663b9ff55afed566dbc9f6f2d1ebe89fe83363d9bfca24f800b6da8"

		sealedCap = "9028d1a9a4957af65eca21e627b87f5d1afcd7f2c2a76205fb07ee87d0e6e03e"
		sealedD   = 0.40116427497012386
	)
	sealedDS := []float64{
		0.035962756128103845,
		0.9184957919746071,
		0.9532820059715236,
	}

	if gotPub, err := PublicKeyFromPrivate(alicePriv); err != nil || gotPub != alicePub {
		t.Fatalf("alice public key = (%q, %v), want %q", gotPub, err, alicePub)
	}
	if gotPub, err := PublicKeyFromPrivate(bobPriv); err != nil || gotPub != bobPub {
		t.Fatalf("bob public key = (%q, %v), want %q", gotPub, err, bobPub)
	}

	gotCtx, err := DeriveSharedSalt(alicePriv, bobPub, WithContext("chan-1"))
	if err != nil || gotCtx != wantSharedCtx {
		t.Fatalf("DeriveSharedSalt(ctx) = (%q, %v), want %q", gotCtx, err, wantSharedCtx)
	}
	gotNoCtx, err := DeriveSharedSalt(bobPriv, alicePub)
	if err != nil || gotNoCtx != wantSharedNoCtx {
		t.Fatalf("DeriveSharedSalt(no ctx) = (%q, %v), want %q", gotNoCtx, err, wantSharedNoCtx)
	}

	decCipher, err := OpenSession(sealedCap, bobPriv, WithContext("table:users"))
	if err != nil {
		t.Fatalf("OpenSession(Python capsule) failed: %v", err)
	}
	gotBits, err := decCipher.Decrypt(sealedD)
	wantBits := []bool{true, false, true, true, false, true}
	if err != nil || !equalBools(gotBits, wantBits) {
		t.Fatalf("Decrypt(Python sealedD) = (%v, %v), want %v", gotBits, err, wantBits)
	}

	gotMany, err := decCipher.Deserialize(sealedDS)
	wantMany := make([]bool, 25)
	for i := range wantMany {
		wantMany[i] = i%3 == 0
	}
	if err != nil || !equalBools(gotMany, wantMany) {
		t.Fatalf("Deserialize(Python sealedDS) = (%v, %v), want %v", gotMany, err, wantMany)
	}
}
