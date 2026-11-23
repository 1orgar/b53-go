package b53

import (
	"errors"
	"math"
	"math/rand/v2"
	"strconv"
	"testing"
)

func chainedChunkLengths(t *testing.T, doubles []float64, salt string) []int {
	t.Helper()
	keyBytes, err := normalizeSalt(salt)
	if err != nil {
		t.Fatalf("normalizeSalt failed: %v", err)
	}
	seed := deriveInitialSeed(keyBytes, len(doubles))
	lengths := make([]int, 0, len(doubles))
	prevLen := 0
	for idx, val := range doubles {
		if idx > 0 {
			seed = deriveNextSeed(keyBytes, seed, idx, prevLen)
		}
		bits, err := decryptWithKey(val, seed)
		if err != nil {
			t.Fatalf("decryptWithKey at chunk %d failed: %v", idx, err)
		}
		prevLen = len(bits)
		lengths = append(lengths, prevLen)
	}
	return lengths
}

func TestDefaultSerializeConstants(t *testing.T) {
	if DefaultChunkMin != 10 {
		t.Fatalf("DefaultChunkMin = %d, want 10", DefaultChunkMin)
	}
	if MinSplitSize != 2 {
		t.Fatalf("MinSplitSize = %d, want 2", MinSplitSize)
	}
}

func TestSerializeDeserializeVariousLengths(t *testing.T) {
	salt, err := GenerateSalt(DefaultSaltBytes)
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewPCG(12345, 67890))

	lengths := []int{0, 1, 5, 9, 10, 11, 12, 19, 20, 30, 50, 51, 137, 1000}
	for _, length := range lengths {
		bits := make([]bool, length)
		for i := range length {
			bits[i] = rng.IntN(2) == 1
		}

		doubles, err := Serialize(bits, salt)
		if err != nil {
			t.Fatalf("Serialize(len=%d) error: %v", length, err)
		}
		expectedChunks := 0
		if length > 0 {
			expectedChunks = (length / DefaultChunkMin) + 1
		}
		if len(doubles) != expectedChunks {
			t.Fatalf("len=%d: got %d chunks, want %d", length, len(doubles), expectedChunks)
		}

		for _, val := range doubles {
			if math.IsNaN(val) || math.IsInf(val, 0) || val < 0.0 || val >= 1.0 {
				t.Fatalf("serialized float %v out of [0.0, 1.0)", val)
			}
			scaled := math.Ldexp(val, MantissaBits)
			if math.Trunc(scaled) != scaled {
				t.Fatalf("serialized float %v not on 2^-53 grid", val)
			}
		}

		restored, err := Deserialize(doubles, salt)
		if err != nil {
			t.Fatalf("Deserialize(len=%d) error: %v", length, err)
		}
		if !equalBools(restored, bits) {
			t.Fatalf("Deserialize(len=%d) mismatch", length)
		}
	}
}

func TestPlannerFixedCountAndFirstChunkBound(t *testing.T) {
	for _, minSize := range []int{2, 3, 10, 50} {
		for total := 1; total < 105; total++ {
			chunkSizes, err := planChunkSizes(total, minSize)
			if err != nil {
				t.Fatalf("planChunkSizes(%d, %d) failed: %v", total, minSize, err)
			}
			wantCount := (total / minSize) + 1
			if len(chunkSizes) != wantCount {
				t.Fatalf("planChunkSizes(%d, %d) len = %d, want %d", total, minSize, len(chunkSizes), wantCount)
			}
			sum := 0
			for i, s := range chunkSizes {
				sum += s
				if i == 0 && (s < 1 || s >= minSize) {
					t.Fatalf("first chunk size = %d, want 1 <= s < %d", s, minSize)
				}
				if i > 0 && (s < 1 || s > minSize) {
					t.Fatalf("chunk[%d] size = %d, want 1 <= s <= %d", i, s, minSize)
				}
			}
			if sum != total {
				t.Fatalf("sum(chunkSizes) = %d, want %d", sum, total)
			}
		}
	}
}

func TestTwelveElementsWithMinSize10(t *testing.T) {
	salt, _ := GenerateSalt(DefaultSaltBytes)
	bits := make([]bool, 12)
	for i := range bits {
		bits[i] = i%3 == 0
	}

	seenSplits := make(map[string]struct{})
	for range 40 {
		doubles, err := Serialize(bits, salt, WithMinSize(10))
		if err != nil {
			t.Fatal(err)
		}
		lens := chainedChunkLengths(t, doubles, salt)
		if len(lens) != 2 || lens[0]+lens[1] != 12 {
			t.Fatalf("unexpected chunk lengths: %v", lens)
		}
		if lens[0] < 1 || lens[0] >= 10 || lens[1] < 1 || lens[1] > 10 {
			t.Fatalf("chunk lengths out of bounds: %v", lens)
		}
		restored, err := Deserialize(doubles, salt)
		if err != nil || !equalBools(restored, bits) {
			t.Fatalf("Deserialize failed: %v", err)
		}
		seenSplits[strconv.Itoa(lens[0])+","+strconv.Itoa(lens[1])] = struct{}{}
	}
	if len(seenSplits) <= 1 {
		t.Fatalf("expected multiple random splits across 40 trials, got %v", seenSplits)
	}
}

func TestDivisibleLengthsAddExtraChunkWithRandomSizes(t *testing.T) {
	salt, _ := GenerateSalt(DefaultSaltBytes)
	for _, total := range []int{10, 20, 30} {
		bits := make([]bool, total)
		for i := range bits {
			bits[i] = i%2 == 1
		}
		seenSplits := make(map[string]struct{})
		for range 30 {
			doubles, err := Serialize(bits, salt, WithMinSize(10))
			if err != nil {
				t.Fatal(err)
			}
			lens := chainedChunkLengths(t, doubles, salt)
			if len(lens) != (total/10)+1 {
				t.Fatalf("total=%d: chunk count = %d, want %d", total, len(lens), (total/10)+1)
			}
			key := ""
			sum := 0
			for i, l := range lens {
				sum += l
				if i == 0 && (l < 1 || l >= 10) {
					t.Fatalf("lens[0] = %d out of [1, 9]", l)
				}
				if i > 0 && (l < 1 || l > 10) {
					t.Fatalf("lens[%d] = %d out of [1, 10]", i, l)
				}
				key += strconv.Itoa(l) + ","
			}
			if sum != total {
				t.Fatalf("sum = %d, want %d", sum, total)
			}
			restored, err := Deserialize(doubles, salt)
			if err != nil || !equalBools(restored, bits) {
				t.Fatalf("Deserialize failed: %v", err)
			}
			seenSplits[key] = struct{}{}
		}
		if len(seenSplits) <= 1 {
			t.Fatalf("total=%d: expected random splits, got %v", total, seenSplits)
		}
	}
}

func TestCannotDecryptIndividualChunksOrTamperedSequences(t *testing.T) {
	salt, _ := GenerateSalt(DefaultSaltBytes)

	// Even for a single-chunk array (K=1), seed_0 differs from raw salt.
	shortBits := []bool{true, false, true, true, false}
	mismatchesSingle := 0
	for range 10 {
		doubles, err := Serialize(shortBits, salt, WithMinSize(10))
		if err != nil {
			t.Fatal(err)
		}
		dec, err := Decrypt(doubles[0], salt)
		if err != nil {
			t.Fatal(err)
		}
		if !equalBools(dec, shortBits) {
			mismatchesSingle++
		}
	}
	if mismatchesSingle != 10 {
		t.Fatalf("mismatchesSingle = %d, want 10", mismatchesSingle)
	}

	// Multi-chunk array: cannot decrypt any chunk alone, nor truncate, drop, or reorder.
	bits := make([]bool, 45)
	for i := range bits {
		bits[i] = i%3 == 0
	}
	doubles, err := Serialize(bits, salt, WithMinSize(10))
	if err != nil {
		t.Fatal(err)
	}
	if len(doubles) != 5 {
		t.Fatalf("len(doubles) = %d, want 5", len(doubles))
	}

	chunkLens := chainedChunkLengths(t, doubles, salt)
	chunks := make([][]bool, len(chunkLens))
	pos := 0
	for i, sz := range chunkLens {
		chunks[i] = bits[pos : pos+sz]
		pos += sz
	}

	for idx, d := range doubles {
		decRaw, _ := Decrypt(d, salt)
		if equalBools(decRaw, chunks[idx]) {
			t.Fatalf("Decrypt(doubles[%d], salt) unexpectedly matched chunk", idx)
		}
		decSingle, _ := Deserialize([]float64{d}, salt)
		if equalBools(decSingle, chunks[idx]) {
			t.Fatalf("Deserialize([doubles[%d]], salt) unexpectedly matched chunk", idx)
		}
	}

	// Truncation changes totalChunks -> breaks seed_0 and all subsequent chunks.
	trunc, _ := Deserialize(doubles[:len(doubles)-1], salt)
	if equalBools(trunc, bits[:len(bits)-chunkLens[len(chunkLens)-1]]) {
		t.Fatal("truncated sequence unexpectedly decrypted cleanly")
	}

	// Dropping chunk 0 shifts indices and breaks seed chain.
	dropped, _ := Deserialize(doubles[1:], salt)
	if equalBools(dropped, bits[chunkLens[0]:]) {
		t.Fatal("shifted sequence unexpectedly decrypted cleanly")
	}

	// Swapping chunks breaks chaining.
	swapped := append([]float64(nil), doubles...)
	swapped[1], swapped[2] = swapped[2], swapped[1]
	resSwapped, _ := Deserialize(swapped, salt)
	if equalBools(resSwapped, bits) {
		t.Fatal("swapped sequence unexpectedly decrypted to original bits")
	}
}

func TestCipherSerializeAndDeserialize(t *testing.T) {
	cipher, _, err := GenerateCipher(DefaultSaltBytes)
	if err != nil {
		t.Fatal(err)
	}
	expected := make([]bool, 95)
	for i := range expected {
		expected[i] = i%4 == 0
	}

	doubles, err := cipher.Serialize(expected, WithMinSize(8))
	if err != nil {
		t.Fatal(err)
	}
	if len(doubles) != (95/8)+1 {
		t.Fatalf("len(doubles) = %d, want %d", len(doubles), (95/8)+1)
	}
	restored, err := cipher.Deserialize(doubles)
	if err != nil {
		t.Fatal(err)
	}
	if !equalBools(restored, expected) {
		t.Fatal("cipher.Deserialize mismatch")
	}

	// Cross-compatibility with Python golden serialized vector.
	const pySalt = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	pyDoubles := []float64{
		0.13237114394738403,
		0.04478107854016122,
		0.0005021423787280321,
		0.3454268107565478,
		0.954379811531092,
	}
	gotPy, err := Deserialize(pyDoubles, pySalt)
	if err != nil {
		t.Fatalf("Deserialize(Python vector) failed: %v", err)
	}
	if FormatBits(gotPy) != "01001010010100101001010010100101001010010100101" {
		t.Fatalf("Deserialize(Python vector) = %q", FormatBits(gotPy))
	}
}

func TestSerializeValidation(t *testing.T) {
	salt, _ := GenerateSalt(DefaultSaltBytes)

	for _, badMinSize := range []int{-5, 0, 1, MaxLen + 1, 100} {
		if _, err := Serialize([]bool{true, false}, salt, WithMinSize(badMinSize)); !errors.Is(err, ErrInvalidMinSize) {
			t.Fatalf("Serialize(minSize=%d) err = %v, want ErrInvalidMinSize", badMinSize, err)
		}
		if _, err := Serialize(nil, salt, WithMinSize(badMinSize)); !errors.Is(err, ErrInvalidMinSize) {
			t.Fatalf("Serialize(nil, minSize=%d) err = %v, want ErrInvalidMinSize", badMinSize, err)
		}
	}

	if _, err := Serialize(nil, ""); !errors.Is(err, ErrEmptySalt) {
		t.Fatalf("Serialize(nil, \"\") err = %v, want ErrEmptySalt", err)
	}
	if _, err := Deserialize(nil, ""); !errors.Is(err, ErrEmptySalt) {
		t.Fatalf("Deserialize(nil, \"\") err = %v, want ErrEmptySalt", err)
	}
	if _, err := Deserialize([]float64{0.5, 1.0}, salt); !errors.Is(err, ErrInvalidDouble) {
		t.Fatalf("Deserialize([0.5, 1.0]) err = %v, want ErrInvalidDouble", err)
	}

	var nilCipher *Cipher
	if _, err := nilCipher.Serialize([]bool{true}); !errors.Is(err, ErrNilCipher) {
		t.Fatalf("nilCipher.Serialize err = %v, want ErrNilCipher", err)
	}
	if _, err := nilCipher.Deserialize([]float64{0.5}); !errors.Is(err, ErrNilCipher) {
		t.Fatalf("nilCipher.Deserialize err = %v, want ErrNilCipher", err)
	}
}
