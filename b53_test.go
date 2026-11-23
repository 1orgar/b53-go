package b53

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"testing"
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

func TestPartitionCoversEntire53BitSpace(t *testing.T) {
	counts := NonceCounts()
	baseMap := Bases()
	sizeMap := Sizes()

	if len(counts) != MaxLen || len(baseMap) != MaxLen || len(sizeMap) != MaxLen {
		t.Fatalf("unexpected table sizes: counts=%d bases=%d sizes=%d", len(counts), len(baseMap), len(sizeMap))
	}

	var total uint64
	for length := MinLen; length <= MaxLen; length++ {
		c, ok := counts[length]
		if !ok {
			t.Fatalf("missing length %d in NonceCounts()", length)
		}
		total += c * (uint64(1) << length)
	}
	if total != StateSpace {
		t.Fatalf("partition total = %d, want %d", total, StateSpace)
	}
	if StateSpace != (uint64(1) << MantissaBits) {
		t.Fatalf("StateSpace = %d, want 2^%d", StateSpace, MantissaBits)
	}
}

func TestPartitionRangesAreContiguousAndDisjoint(t *testing.T) {
	counts := NonceCounts()
	baseMap := Bases()
	sizeMap := Sizes()

	if baseMap[1] != 0 {
		t.Fatalf("Bases()[1] = %d, want 0", baseMap[1])
	}

	for length := MinLen; length <= MaxLen; length++ {
		if counts[length] < 3 {
			t.Fatalf("NonceCounts()[%d] = %d, want >= 3", length, counts[length])
		}
		gotNonce, err := NonceCount(length)
		if err != nil || gotNonce != counts[length] {
			t.Fatalf("NonceCount(%d) = (%d, %v), want (%d, nil)", length, gotNonce, err, counts[length])
		}
		if sizeMap[length] != (counts[length] << length) {
			t.Fatalf("Sizes()[%d] = %d, want %d", length, sizeMap[length], counts[length]<<length)
		}
		if length < MaxLen {
			if baseMap[length]+sizeMap[length] != baseMap[length+1] {
				t.Fatalf("gap/overlap at length %d", length)
			}
		}
	}

	if baseMap[MaxLen]+sizeMap[MaxLen] != StateSpace {
		t.Fatalf("last segment ends at %d, want %d", baseMap[MaxLen]+sizeMap[MaxLen], StateSpace)
	}

	// Mutating returned maps must not affect internal tables.
	counts[1] = 0
	baseMap[1] = 999
	sizeMap[1] = 0
	if fresh, _ := NonceCount(1); fresh == 0 {
		t.Fatal("mutating NonceCounts() map affected internal table")
	}
	if Bases()[1] != 0 || Sizes()[1] == 0 {
		t.Fatal("mutating Bases()/Sizes() map affected internal table")
	}

	for _, badLen := range []int{-1, 0, MaxLen + 1, 100} {
		if _, err := NonceCount(badLen); !errors.Is(err, ErrInvalidLength) {
			t.Fatalf("NonceCount(%d) error = %v, want ErrInvalidLength", badLen, err)
		}
	}
}

func TestPartitionMatchesSpecificationReferenceValues(t *testing.T) {
	expected := map[int]uint64{
		50: 3,
		49: 3,
		48: 3,
		47: 5,
		45: 13,
		40: 100,
		30: 5_811,
		20: 335_103,
		10: 19_323_738,
		1:  2_971_477_630,
	}
	counts := NonceCounts()
	for length, want := range expected {
		if counts[length] != want {
			t.Fatalf("NonceCounts()[%d] = %d, want %d", length, counts[length], want)
		}
	}
}

func TestRoundtripAllLengths1To50(t *testing.T) {
	salt, err := GenerateSalt(DefaultSaltBytes)
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}
	rng := rand.New(rand.NewPCG(42, 99))

	for length := MinLen; length <= MaxLen; length++ {
		allFalse := make([]bool, length)
		allTrue := make([]bool, length)
		alt := make([]bool, length)
		rnd := make([]bool, length)
		for i := range length {
			allTrue[i] = true
			alt[i] = i%2 == 0
			rnd[i] = rng.IntN(2) == 1
		}

		for _, bits := range [][]bool{allFalse, allTrue, alt, rnd} {
			encoded, err := Encrypt(bits, salt)
			if err != nil {
				t.Fatalf("Encrypt(len=%d) error: %v", length, err)
			}
			if math.IsNaN(encoded) || math.IsInf(encoded, 0) || encoded < 0.0 || encoded >= 1.0 {
				t.Fatalf("encoded %v out of [0.0, 1.0)", encoded)
			}
			scaled := math.Ldexp(encoded, MantissaBits)
			if math.Trunc(scaled) != scaled {
				t.Fatalf("encoded %v not on 2^-53 grid", encoded)
			}

			// Exact preservation via strconv.FormatFloat(..., 'g', -1, 64) and JSON.
			s := strconv.FormatFloat(encoded, 'g', -1, 64)
			parsed, err := strconv.ParseFloat(s, 64)
			if err != nil {
				t.Fatalf("ParseFloat(%q) failed: %v", s, err)
			}
			restored, err := Decrypt(parsed, salt)
			if err != nil {
				t.Fatalf("Decrypt(len=%d) failed: %v", length, err)
			}
			if !equalBools(restored, bits) {
				t.Fatalf("roundtrip mismatch at len=%d: got %v, want %v", length, restored, bits)
			}

			jsonBytes, err := json.Marshal(encoded)
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}
			var jsonDecoded float64
			if err := json.Unmarshal(jsonBytes, &jsonDecoded); err != nil {
				t.Fatalf("json.Unmarshal failed: %v", err)
			}
			restoredJSON, err := Decrypt(jsonDecoded, salt)
			if err != nil {
				t.Fatalf("Decrypt(json len=%d) failed: %v", length, err)
			}
			if !equalBools(restoredJSON, bits) {
				t.Fatalf("JSON roundtrip mismatch at len=%d", length)
			}
		}
	}
}

func TestExhaustiveSmallLengths1To4(t *testing.T) {
	const salt = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	for length := 1; length <= 4; length++ {
		totalCombos := 1 << length
		for mask := range totalCombos {
			bits := make([]bool, length)
			for i := range length {
				bits[i] = ((mask >> i) & 1) == 1
			}
			encoded, err := Encrypt(bits, salt)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}
			decoded, err := Decrypt(encoded, salt)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}
			if !equalBools(decoded, bits) {
				t.Fatalf("len=%d mask=%d mismatch: got %v, want %v", length, mask, decoded, bits)
			}
		}
	}
}

func TestNonceProducesDistinctOutputsForSameInput(t *testing.T) {
	salt, err := GenerateSalt(DefaultSaltBytes)
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}
	bits := []bool{true, false, true, true, false, false, true, false, true, true}

	outputs := make(map[float64]struct{}, 25)
	for range 25 {
		v, err := Encrypt(bits, salt)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}
		outputs[v] = struct{}{}
		dec, err := Decrypt(v, salt)
		if err != nil || !equalBools(dec, bits) {
			t.Fatalf("Decrypt(%v) = (%v, %v), want %v", v, dec, err, bits)
		}
	}
	if len(outputs) <= 20 {
		t.Fatalf("expected > 20 distinct outputs at L=10, got %d", len(outputs))
	}

	bits50 := make([]bool, 50)
	for i := range bits50 {
		bits50[i] = i%3 == 0
	}
	outputs50 := make(map[float64]struct{}, 32)
	for range 32 {
		v, err := Encrypt(bits50, salt)
		if err != nil {
			t.Fatalf("Encrypt(L=50) failed: %v", err)
		}
		outputs50[v] = struct{}{}
		dec, err := Decrypt(v, salt)
		if err != nil || !equalBools(dec, bits50) {
			t.Fatalf("Decrypt(L=50) mismatch: %v", err)
		}
	}
	if len(outputs50) < 2 {
		t.Fatalf("expected >= 2 distinct outputs at L=50, got %d", len(outputs50))
	}
}

func TestSaltFormatsAndCrossCompatibility(t *testing.T) {
	type customStringSalt string
	type customByteSalt []byte

	hexSalt := strings.Repeat("DeadBeef", 8)
	rawBytes, err := hex.DecodeString(hexSalt)
	if err != nil {
		t.Fatalf("DecodeString failed: %v", err)
	}
	bits := []bool{true, false, true, false, true}

	encoded, err := Encrypt(bits, "  "+hexSalt+" \n")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if dec, err := Decrypt(encoded, rawBytes); err != nil || !equalBools(dec, bits) {
		t.Fatalf("Decrypt with rawBytes failed: %v", err)
	}
	if dec, err := Decrypt(encoded, customByteSalt(rawBytes)); err != nil || !equalBools(dec, bits) {
		t.Fatalf("Decrypt with customByteSalt failed: %v", err)
	}

	// Whitespace between hex byte pairs matches Python bytes.fromhex; whitespace inside a pair falls back to UTF-8.
	spacedHex := "de ad\nbe\tef"
	encSpaced, err := Encrypt(bits, spacedHex)
	if err != nil {
		t.Fatalf("Encrypt(spacedHex) failed: %v", err)
	}
	if dec, err := Decrypt(encSpaced, []byte{0xde, 0xad, 0xbe, 0xef}); err != nil || !equalBools(dec, bits) {
		t.Fatalf("spaced hex did not match raw bytes: %v", err)
	}

	brokenPair := "a bc"
	encBroken, err := Encrypt(bits, brokenPair)
	if err != nil {
		t.Fatalf("Encrypt(brokenPair) failed: %v", err)
	}
	if dec, err := Decrypt(encBroken, []byte(brokenPair)); err != nil || !equalBools(dec, bits) {
		t.Fatalf("broken hex pair did not fall back to UTF-8: %v", err)
	}

	passphrase := "correct-horse-battery-staple"
	encUTF8, err := Encrypt(bits, passphrase)
	if err != nil {
		t.Fatalf("Encrypt(passphrase) failed: %v", err)
	}
	if dec, err := Decrypt(encUTF8, []byte(passphrase)); err != nil || !equalBools(dec, bits) {
		t.Fatalf("Decrypt(utf8 bytes) failed: %v", err)
	}
	if dec, err := Decrypt(encUTF8, customStringSalt(passphrase)); err != nil || !equalBools(dec, bits) {
		t.Fatalf("Decrypt(customStringSalt) failed: %v", err)
	}

	// Mutating caller byte slice after NewCipher must not mutate cipher key.
	keyCopy := append([]byte(nil), rawBytes...)
	cipher, err := NewCipher(keyCopy)
	if err != nil {
		t.Fatalf("NewCipher(keyCopy) failed: %v", err)
	}
	for i := range keyCopy {
		keyCopy[i] = 0
	}
	encCopy, err := cipher.Encrypt(bits)
	if err != nil {
		t.Fatalf("cipher.Encrypt failed: %v", err)
	}
	if dec, err := Decrypt(encCopy, rawBytes); err != nil || !equalBools(dec, bits) {
		t.Fatalf("cipher key was mutated through caller slice: %v", err)
	}
}

func TestWrongSaltChangesRecoveredPayload(t *testing.T) {
	saltA, _ := GenerateSalt(DefaultSaltBytes)
	saltB, _ := GenerateSalt(DefaultSaltBytes)
	bits := []bool{true, false, true, true, false, true, false, true, true, false}

	mismatches := 0
	for range 10 {
		encoded, err := Encrypt(bits, saltA)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}
		recovered, err := Decrypt(encoded, saltB)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}
		if !equalBools(recovered, bits) {
			mismatches++
		}
	}
	if mismatches != 10 {
		t.Fatalf("mismatches = %d, want 10", mismatches)
	}
}

func TestEncryptAndSaltValidation(t *testing.T) {
	salt, _ := GenerateSalt(DefaultSaltBytes)

	if _, err := Encrypt(nil, salt); !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("Encrypt(nil) err = %v, want ErrInvalidLength", err)
	}
	if _, err := Encrypt([]bool{}, salt); !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("Encrypt([]) err = %v, want ErrInvalidLength", err)
	}
	if _, err := Encrypt(make([]bool, MaxLen+1), salt); !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("Encrypt(51) err = %v, want ErrInvalidLength", err)
	}

	bits := []bool{true}
	for _, badStr := range []string{"", "   \t\n "} {
		if _, err := Encrypt(bits, badStr); !errors.Is(err, ErrEmptySalt) {
			t.Fatalf("Encrypt(salt=%q) err = %v, want ErrEmptySalt", badStr, err)
		}
		if _, err := Decrypt(0.5, badStr); !errors.Is(err, ErrEmptySalt) {
			t.Fatalf("Decrypt(salt=%q) err = %v, want ErrEmptySalt", badStr, err)
		}
		if _, err := NewCipher(badStr); !errors.Is(err, ErrEmptySalt) {
			t.Fatalf("NewCipher(salt=%q) err = %v, want ErrEmptySalt", badStr, err)
		}
	}
	for _, badBytes := range [][]byte{nil, {}} {
		if _, err := Encrypt(bits, badBytes); !errors.Is(err, ErrEmptySalt) {
			t.Fatalf("Encrypt(empty bytes) err = %v, want ErrEmptySalt", err)
		}
		if _, err := NewCipher(badBytes); !errors.Is(err, ErrEmptySalt) {
			t.Fatalf("NewCipher(empty bytes) err = %v, want ErrEmptySalt", err)
		}
	}
}

func TestDecryptInputValidationAndBoundaryGridPoints(t *testing.T) {
	salt, _ := GenerateSalt(DefaultSaltBytes)

	badVals := []float64{
		math.NaN(),
		math.Inf(1),
		math.Inf(-1),
		-0.1,
		-math.Ldexp(1, -53),
		1.0,
		1.5,
		0.3,
		math.Ldexp(1, -54),
		math.SmallestNonzeroFloat64,
	}
	for _, bad := range badVals {
		if _, err := Decrypt(bad, salt); !errors.Is(err, ErrInvalidDouble) {
			t.Fatalf("Decrypt(%v) err = %v, want ErrInvalidDouble", bad, err)
		}
	}

	edges := []float64{
		0.0,
		math.Copysign(0, -1), // -0.0
		math.Ldexp(float64((uint64(1)<<53)-1), -53),
	}
	for _, edge := range edges {
		restored, err := Decrypt(edge, salt)
		if err != nil {
			t.Fatalf("Decrypt(edge=%v) unexpected error: %v", edge, err)
		}
		if len(restored) < MinLen || len(restored) > MaxLen {
			t.Fatalf("Decrypt(edge=%v) invalid length %d", edge, len(restored))
		}
	}
}

func TestCipherStructRedactionAndZeroNilSafety(t *testing.T) {
	cipher, salt, err := GenerateCipher(DefaultSaltBytes)
	if err != nil {
		t.Fatalf("GenerateCipher failed: %v", err)
	}
	if cipher.KeyLen() != DefaultSaltBytes {
		t.Fatalf("KeyLen() = %d, want %d", cipher.KeyLen(), DefaultSaltBytes)
	}

	strRepr := cipher.String()
	goRepr := fmt.Sprintf("%#v", cipher)
	if strings.Contains(strRepr, salt) || strings.Contains(goRepr, salt) {
		t.Fatal("secret salt leaked in String()/GoString()")
	}
	if !strings.Contains(strRepr, "key_bytes=32") {
		t.Fatalf("unexpected String(): %q", strRepr)
	}
	if !strings.Contains(goRepr, "len=32") {
		t.Fatalf("unexpected GoString(): %q", goRepr)
	}

	val, err := cipher.EncryptString("1011001")
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}
	strOut, err := cipher.DecryptString(val)
	if err != nil || strOut != "1011001" {
		t.Fatalf("DecryptString = (%q, %v), want %q", strOut, err, "1011001")
	}
	sliceOut, err := cipher.Decrypt(val)
	want := []bool{true, false, true, true, false, false, true}
	if err != nil || !equalBools(sliceOut, want) {
		t.Fatalf("Decrypt = (%v, %v), want %v", sliceOut, err, want)
	}

	var nilCipher *Cipher
	if nilCipher.KeyLen() != 0 {
		t.Fatalf("nilCipher.KeyLen() = %d, want 0", nilCipher.KeyLen())
	}
	if nilCipher.String() != "Cipher(<nil>)" {
		t.Fatalf("nilCipher.String() = %q", nilCipher.String())
	}
	if nilCipher.GoString() != "(*b53.Cipher)(nil)" {
		t.Fatalf("nilCipher.GoString() = %q", nilCipher.GoString())
	}
	if _, err := nilCipher.Encrypt(want); !errors.Is(err, ErrNilCipher) {
		t.Fatalf("nilCipher.Encrypt err = %v, want ErrNilCipher", err)
	}
	if _, err := nilCipher.Decrypt(0.5); !errors.Is(err, ErrNilCipher) {
		t.Fatalf("nilCipher.Decrypt err = %v, want ErrNilCipher", err)
	}
	if _, err := nilCipher.EncryptString("101"); !errors.Is(err, ErrNilCipher) {
		t.Fatalf("nilCipher.EncryptString err = %v, want ErrNilCipher", err)
	}
	if _, err := nilCipher.DecryptString(0.5); !errors.Is(err, ErrNilCipher) {
		t.Fatalf("nilCipher.DecryptString err = %v, want ErrNilCipher", err)
	}

	var zeroCipher Cipher
	if _, err := zeroCipher.Encrypt(want); !errors.Is(err, ErrEmptySalt) {
		t.Fatalf("zeroCipher.Encrypt err = %v, want ErrEmptySalt", err)
	}
	if _, err := zeroCipher.Decrypt(0.5); !errors.Is(err, ErrEmptySalt) {
		t.Fatalf("zeroCipher.Decrypt err = %v, want ErrEmptySalt", err)
	}
}

func TestCipherConcurrency(t *testing.T) {
	cipher, _, err := GenerateCipher(DefaultSaltBytes)
	if err != nil {
		t.Fatalf("GenerateCipher failed: %v", err)
	}
	bits := []bool{true, false, true, true, false, true, false, false, true, true}

	var wg sync.WaitGroup
	for g := range 16 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := range 100 {
				x, err := cipher.Encrypt(bits)
				if err != nil {
					t.Errorf("goroutine %d iter %d Encrypt error: %v", id, i, err)
					return
				}
				got, err := cipher.Decrypt(x)
				if err != nil {
					t.Errorf("goroutine %d iter %d Decrypt error: %v", id, i, err)
					return
				}
				if !equalBools(got, bits) {
					t.Errorf("goroutine %d iter %d roundtrip mismatch", id, i)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestGenerateSaltValidation(t *testing.T) {
	s32, err := GenerateSalt(DefaultSaltBytes)
	if err != nil {
		t.Fatalf("GenerateSalt(32) error: %v", err)
	}
	if len(s32) != 64 {
		t.Fatalf("len(s32) = %d, want 64", len(s32))
	}
	if _, err := hex.DecodeString(s32); err != nil {
		t.Fatalf("s32 is not valid hex: %v", err)
	}

	s16, err := GenerateSalt(MinSaltBytes)
	if err != nil || len(s16) != 32 {
		t.Fatalf("GenerateSalt(16) = (%q, %v)", s16, err)
	}
	other, _ := GenerateSalt(DefaultSaltBytes)
	if s32 == other {
		t.Fatal("two consecutive GenerateSalt calls returned identical values")
	}

	for _, badSize := range []int{-5, 0, 15} {
		if _, err := GenerateSalt(badSize); !errors.Is(err, ErrSaltTooShort) {
			t.Fatalf("GenerateSalt(%d) err = %v, want ErrSaltTooShort", badSize, err)
		}
	}
}

func TestParseAndFormatBits(t *testing.T) {
	cases := []struct {
		raw  string
		want []bool
	}{
		{"1011001", []bool{true, false, true, true, false, false, true}},
		{"  0101 \n", []bool{false, true, false, true}},
		{"true, false, T, f, 1, 0", []bool{true, false, true, false, true, false}},
		{"false", []bool{false}},
		{"1, , 0", []bool{true, false}},
	}
	for _, tc := range cases {
		got, err := ParseBits(tc.raw)
		if err != nil {
			t.Fatalf("ParseBits(%q) unexpected error: %v", tc.raw, err)
		}
		if !equalBools(got, tc.want) {
			t.Fatalf("ParseBits(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}

	if got := FormatBits([]bool{true, false, true, true}); got != "1011" {
		t.Fatalf("FormatBits = %q, want %q", got, "1011")
	}
	if got := FormatBits(nil); got != "" {
		t.Fatalf("FormatBits(nil) = %q, want empty", got)
	}

	for _, bad := range []string{"", "   ", ",", " , ", "1,maybe", "102"} {
		if _, err := ParseBits(bad); !errors.Is(err, ErrInvalidBitString) {
			t.Fatalf("ParseBits(%q) err = %v, want ErrInvalidBitString", bad, err)
		}
	}
}

func TestVersionConstant(t *testing.T) {
	if Version != "0.1.0" {
		t.Fatalf("Version = %q, want %q", Version, "0.1.0")
	}
}

func BenchmarkCipherEncrypt(b *testing.B) {
	cipher, _, err := GenerateCipher(DefaultSaltBytes)
	if err != nil {
		b.Fatal(err)
	}
	bits := []bool{true, false, true, true, false, false, true, false, true, true}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cipher.Encrypt(bits); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCipherDecrypt(b *testing.B) {
	cipher, _, err := GenerateCipher(DefaultSaltBytes)
	if err != nil {
		b.Fatal(err)
	}
	bits := []bool{true, false, true, true, false, false, true, false, true, true}
	encoded, err := cipher.Encrypt(bits)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cipher.Decrypt(encoded); err != nil {
			b.Fatal(err)
		}
	}
}
