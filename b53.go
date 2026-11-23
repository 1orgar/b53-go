// Package b53 implements reversible 53-bit cryptographic packing of boolean
// arrays (length 1..50) with hidden length and random nonce into an IEEE 754
// binary64 float64 in the half-open interval [0.0, 1.0).
package b53

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strings"
)

const (
	// Version is the semantic version of the b53-go library and CLI.
	Version = "0.1.0"

	// MantissaBits is the number of exact significand bits in [0.0, 1.0) on the 2^-53 grid.
	MantissaBits = 53

	// MinLen is the minimum supported boolean array length.
	MinLen = 1

	// MaxLen is the maximum supported boolean array length.
	MaxLen = 50

	// StateSpace is the total number of 53-bit states (2^53).
	StateSpace uint64 = 1 << MantissaBits

	// DefaultChunkMin is the default chunk-size threshold for Serialize.
	DefaultChunkMin = 10

	// MinSplitSize is the minimum allowed minSize threshold for Serialize.
	MinSplitSize = 2

	// LeftBits is the width in bits of the left Feistel branch.
	LeftBits = 26

	// RightBits is the width in bits of the right Feistel branch (26 + 27 = 53).
	RightBits = 27

	// FeistelRounds is the number of unbalanced Feistel rounds.
	FeistelRounds = 8

	// MinSaltBytes is the minimum byte length accepted by GenerateSalt and DeriveSalt.
	MinSaltBytes = 16

	// DefaultSaltBytes is the default key length in bytes (256 bits) for GenerateSalt and DeriveSalt.
	DefaultSaltBytes = 32

	// DefaultScryptN is the default scrypt CPU/memory cost parameter (32768).
	DefaultScryptN = 1 << 15

	// DefaultScryptR is the default scrypt block size parameter.
	DefaultScryptR = 8

	// DefaultScryptP is the default scrypt parallelization parameter.
	DefaultScryptP = 1

	// DefaultScryptMaxMem is the default scrypt memory cap (128 MiB).
	DefaultScryptMaxMem = 128 * 1024 * 1024

	leftMask  uint64 = (uint64(1) << LeftBits) - 1
	rightMask uint64 = (uint64(1) << RightBits) - 1
)

var (
	// ErrEmptySalt indicates an empty or whitespace-only salt.
	ErrEmptySalt = errors.New("b53: salt must not be empty")

	// ErrSaltTooShort indicates a requested generated or derived salt size below MinSaltBytes.
	ErrSaltTooShort = errors.New("b53: salt size must be at least 16 bytes (128 bits)")

	// ErrInvalidLength indicates a boolean slice outside [MinLen, MaxLen].
	ErrInvalidLength = errors.New("b53: array length must be between 1 and 50 elements")

	// ErrInvalidMinSize indicates a Serialize minSize threshold outside [MinSplitSize, MaxLen].
	ErrInvalidMinSize = errors.New("b53: min_size must be between 2 and 50")

	// ErrInvalidDouble indicates a float64 that is non-finite, outside [0.0, 1.0), or off the 2^-53 grid.
	ErrInvalidDouble = errors.New("b53: invalid IEEE 754 binary64 value")

	// ErrInvalidState indicates a decoded 53-bit plaintext state outside valid partition segments.
	ErrInvalidState = errors.New("b53: failed to decode 53-bit state")

	// ErrInvalidBitString indicates an empty or malformed bit-string representation.
	ErrInvalidBitString = errors.New("b53: invalid bit string")

	// ErrNilCipher indicates an operation invoked on a nil *Cipher receiver.
	ErrNilCipher = errors.New("b53: cipher is nil")

	// ErrEmptyPassword indicates an empty password passed to DeriveSalt or NewCipherFromPassword.
	ErrEmptyPassword = errors.New("b53: password must not be empty")

	// ErrEmptyContext indicates an explicitly provided but empty scrypt context.
	ErrEmptyContext = errors.New("b53: context must not be empty")

	// ErrInvalidScryptParam indicates invalid scrypt parameters (n, r, p, or maxmem).
	ErrInvalidScryptParam = errors.New("b53: invalid scrypt parameter")

	// ErrScryptMemoryLimit indicates scrypt parameters exceeding the configured memory cap.
	ErrScryptMemoryLimit = errors.New("b53: scrypt memory limit exceeded")
)

var (
	nonceCounts [MaxLen + 1]uint64
	bases       [MaxLen + 1]uint64
	sizes       [MaxLen + 1]uint64
	baseList    [MaxLen]uint64
)

func init() {
	buildPartitionTables()
}

func buildPartitionTables() {
	remaining := StateSpace

	for length := MaxLen; length >= 2; length-- {
		unit := uint64(1) << length
		count := remaining / (4 * unit)
		if count < 3 {
			count = 3
		}
		nonceCounts[length] = count
		remaining -= count * unit
	}

	// Remaining budget at L = 1 is guaranteed even and absorbed completely.
	if remaining == 0 || remaining%2 != 0 {
		panic("b53: 53-bit partition integrity check failed at L=1")
	}
	nonceCounts[1] = remaining / 2

	var cursor uint64
	for length := MinLen; length <= MaxLen; length++ {
		size := nonceCounts[length] << length
		bases[length] = cursor
		sizes[length] = size
		baseList[length-1] = cursor
		cursor += size
	}

	if cursor != StateSpace {
		panic("b53: 53-bit partition does not sum to 2^53")
	}
}

// NonceCount returns the number of random nonces available for a boolean array of the given length.
func NonceCount(length int) (uint64, error) {
	if length < MinLen || length > MaxLen {
		return 0, fmt.Errorf("%w: got %d", ErrInvalidLength, length)
	}
	return nonceCounts[length], nil
}

// NonceCounts returns a copy of the nonce counts M_L for all lengths L = 1..50.
func NonceCounts() map[int]uint64 {
	out := make(map[int]uint64, MaxLen)
	for length := MinLen; length <= MaxLen; length++ {
		out[length] = nonceCounts[length]
	}
	return out
}

// Bases returns a copy of the segment start offsets BASE[L] for all lengths L = 1..50.
func Bases() map[int]uint64 {
	out := make(map[int]uint64, MaxLen)
	for length := MinLen; length <= MaxLen; length++ {
		out[length] = bases[length]
	}
	return out
}

// Sizes returns a copy of the segment sizes M_L * 2^L for all lengths L = 1..50.
func Sizes() map[int]uint64 {
	out := make(map[int]uint64, MaxLen)
	for length := MinLen; length <= MaxLen; length++ {
		out[length] = sizes[length]
	}
	return out
}

// Salt constrains secret salt types accepted by Encrypt, Decrypt, and NewCipher:
// either a string (hex-encoded key or UTF-8 passphrase) or raw key bytes.
type Salt interface {
	~string | ~[]byte
}

func normalizeSalt[S Salt](salt S) ([]byte, error) {
	switch v := any(salt).(type) {
	case string:
		return normalizeSaltString(v)
	case []byte:
		if len(v) == 0 {
			return nil, ErrEmptySalt
		}
		return bytes.Clone(v), nil
	default:
		rv := reflect.ValueOf(salt)
		if rv.Kind() == reflect.String {
			return normalizeSaltString(rv.String())
		}
		raw := rv.Bytes()
		if len(raw) == 0 {
			return nil, ErrEmptySalt
		}
		return bytes.Clone(raw), nil
	}
}

func normalizeSaltString(salt string) ([]byte, error) {
	cleaned := strings.TrimSpace(salt)
	if cleaned == "" {
		return nil, ErrEmptySalt
	}
	if decoded, ok := decodePythonHex(cleaned); ok {
		if len(decoded) == 0 {
			return nil, ErrEmptySalt
		}
		return decoded, nil
	}
	return []byte(cleaned), nil
}

// decodePythonHex mirrors Python's bytes.fromhex: ASCII whitespace is allowed
// between byte pairs, not inside a pair; non-hex characters fail decoding.
func decodePythonHex(s string) ([]byte, bool) {
	out := make([]byte, 0, len(s)/2)
	for i := 0; i < len(s); {
		b := s[i]
		if isASCIIWhitespace(b) {
			i++
			continue
		}
		if i+1 >= len(s) {
			return nil, false
		}
		hi, ok1 := hexNibble(b)
		lo, ok2 := hexNibble(s[i+1])
		if !ok1 || !ok2 {
			return nil, false
		}
		out = append(out, (hi<<4)|lo)
		i += 2
	}
	return out, true
}

func isASCIIWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\x0b' || b == '\x0c'
}

func hexNibble(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}

func prf(keyBytes []byte, roundIdx int, halfVal uint32) uint32 {
	var msg [5]byte
	msg[0] = byte(roundIdx)
	binary.BigEndian.PutUint32(msg[1:5], halfVal)

	mac := hmac.New(sha256.New, keyBytes)
	mac.Write(msg[:])

	var digest [sha256.Size]byte
	sum := mac.Sum(digest[:0])
	return binary.BigEndian.Uint32(sum[:4])
}

func feistelEncrypt53(value uint64, keyBytes []byte) uint64 {
	left := (value >> RightBits) & leftMask
	right := value & rightMask
	for r := range FeistelRounds {
		if r%2 == 0 {
			left ^= uint64(prf(keyBytes, r, uint32(right))) & leftMask
		} else {
			right ^= uint64(prf(keyBytes, r, uint32(left))) & rightMask
		}
	}
	return (left << RightBits) | right
}

func feistelDecrypt53(value uint64, keyBytes []byte) uint64 {
	left := (value >> RightBits) & leftMask
	right := value & rightMask
	for r := FeistelRounds - 1; r >= 0; r-- {
		if r%2 == 0 {
			left ^= uint64(prf(keyBytes, r, uint32(right))) & leftMask
		} else {
			right ^= uint64(prf(keyBytes, r, uint32(left))) & rightMask
		}
	}
	return (left << RightBits) | right
}

func randBelow(n uint64) (uint64, error) {
	if n <= 1 {
		return 0, nil
	}
	v, err := rand.Int(rand.Reader, new(big.Int).SetUint64(n))
	if err != nil {
		return 0, fmt.Errorf("b53: random nonce generation failed: %w", err)
	}
	return v.Uint64(), nil
}

func encryptChunk(bits []bool, keyBytes []byte) (float64, error) {
	length := len(bits)
	var dataInt uint64
	for idx, bit := range bits {
		if bit {
			dataInt |= uint64(1) << idx
		}
	}

	nonce, err := randBelow(nonceCounts[length])
	if err != nil {
		return 0, err
	}

	plain53 := bases[length] + (nonce << length) + dataInt
	cipher53 := feistelEncrypt53(plain53, keyBytes)
	return math.Ldexp(float64(cipher53), -MantissaBits), nil
}

func encryptWithKey(bits []bool, keyBytes []byte) (float64, error) {
	length := len(bits)
	if length < MinLen || length > MaxLen {
		return 0, fmt.Errorf("%w: got %d", ErrInvalidLength, length)
	}
	return encryptChunk(bits, keyBytes)
}

func planChunkSizes(total, minSize int) ([]int, error) {
	if total == 0 {
		return nil, nil
	}

	numChunks := (total / minSize) + 1
	caps := make([]int, numChunks)
	caps[0] = minSize - 1
	for i := 1; i < numChunks; i++ {
		caps[i] = minSize
	}

	order := make([]int, numChunks)
	for i := range numChunks {
		order[i] = i
	}
	// Cryptographic Fisher-Yates shuffle.
	for i := numChunks - 1; i > 0; i-- {
		j, err := randBelow(uint64(i + 1))
		if err != nil {
			return nil, err
		}
		order[i], order[int(j)] = order[int(j)], order[i]
	}

	chunkSizes := make([]int, numChunks)
	remaining := total
	remMin := numChunks
	remMax := numChunks*minSize - 1

	for _, idx := range order {
		capVal := caps[idx]
		remMin--
		remMax -= capVal

		lo := max(1, remaining-remMax)
		hi := min(capVal, remaining-remMin)
		delta, err := randBelow(uint64(hi - lo + 1))
		if err != nil {
			return nil, err
		}
		chosen := lo + int(delta)
		chunkSizes[idx] = chosen
		remaining -= chosen
	}

	return chunkSizes, nil
}

func deriveInitialSeed(keyBytes []byte, totalChunks int) []byte {
	var msg [25]byte
	copy(msg[:17], "b53:chain:v1:init")
	binary.BigEndian.PutUint64(msg[17:25], uint64(totalChunks))
	mac := hmac.New(sha256.New, keyBytes)
	mac.Write(msg[:])
	return mac.Sum(nil)
}

func deriveNextSeed(keyBytes, prevSeed []byte, chunkIdx, prevChunkLen int) []byte {
	var msg [58]byte
	copy(msg[:17], "b53:chain:v1:step")
	copy(msg[17:49], prevSeed)
	binary.BigEndian.PutUint64(msg[49:57], uint64(chunkIdx))
	msg[57] = byte(prevChunkLen)
	mac := hmac.New(sha256.New, keyBytes)
	mac.Write(msg[:])
	return mac.Sum(nil)
}

func serializeWithKey(bits []bool, keyBytes []byte, minSize int) ([]float64, error) {
	if minSize < MinSplitSize || minSize > MaxLen {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidMinSize, minSize)
	}
	chunkSizes, err := planChunkSizes(len(bits), minSize)
	if err != nil {
		return nil, err
	}
	if len(chunkSizes) == 0 {
		return []float64{}, nil
	}

	seed := deriveInitialSeed(keyBytes, len(chunkSizes))
	result := make([]float64, 0, len(chunkSizes))
	offset := 0
	for idx, size := range chunkSizes {
		if idx > 0 {
			seed = deriveNextSeed(keyBytes, seed, idx, chunkSizes[idx-1])
		}
		encoded, err := encryptChunk(bits[offset:offset+size], seed)
		if err != nil {
			return nil, err
		}
		result = append(result, encoded)
		offset += size
	}
	return result, nil
}

func deserializeWithKey(values []float64, keyBytes []byte) ([]bool, error) {
	if len(values) == 0 {
		return []bool{}, nil
	}

	seed := deriveInitialSeed(keyBytes, len(values))
	result := make([]bool, 0, len(values)*DefaultChunkMin)
	prevLen := 0
	for idx, doubleVal := range values {
		if idx > 0 {
			seed = deriveNextSeed(keyBytes, seed, idx, prevLen)
		}
		chunkBits, err := decryptWithKey(doubleVal, seed)
		if err != nil {
			return nil, err
		}
		prevLen = len(chunkBits)
		result = append(result, chunkBits...)
	}
	return result, nil
}

func decryptWithKey(doubleVal float64, keyBytes []byte) ([]bool, error) {
	if math.IsNaN(doubleVal) || math.IsInf(doubleVal, 0) || doubleVal < 0.0 || doubleVal >= 1.0 {
		return nil, fmt.Errorf(
			"%w: value must be finite and in the half-open interval [0.0, 1.0)",
			ErrInvalidDouble,
		)
	}

	scaled := math.Ldexp(doubleVal, MantissaBits)
	if math.Trunc(scaled) != scaled {
		return nil, fmt.Errorf(
			"%w: value does not lie on the exact 53-bit IEEE 754 grid",
			ErrInvalidDouble,
		)
	}

	cipher53 := uint64(scaled)
	plain53 := feistelDecrypt53(cipher53, keyBytes)

	length := sort.Search(len(baseList), func(i int) bool {
		return baseList[i] > plain53
	})
	if length < MinLen || length > MaxLen {
		return nil, ErrInvalidState
	}

	base := bases[length]
	if plain53 < base || plain53 >= base+sizes[length] {
		return nil, ErrInvalidState
	}

	offset := plain53 - base
	dataInt := offset & ((uint64(1) << length) - 1)
	result := make([]bool, length)
	for idx := range length {
		result[idx] = ((dataInt >> idx) & 1) == 1
	}
	return result, nil
}

// GenerateSalt generates a cryptographically secure hex-encoded salt of numBytes
// random bytes (at least MinSaltBytes = 16; DefaultSaltBytes = 32 is recommended).
func GenerateSalt(numBytes int) (string, error) {
	if numBytes < MinSaltBytes {
		return "", fmt.Errorf("%w: got %d", ErrSaltTooShort, numBytes)
	}
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("b53: failed to generate salt: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// ParseBits parses a bit string (e.g. "1011001") or comma-separated booleans
// (e.g. "true, false, 1, 0") into a boolean slice.
func ParseBits(raw string) ([]bool, error) {
	cleaned := strings.TrimSpace(raw)
	if cleaned == "" {
		return nil, fmt.Errorf("%w: must not be empty", ErrInvalidBitString)
	}

	allBinary := true
	for i := range len(cleaned) {
		if cleaned[i] != '0' && cleaned[i] != '1' {
			allBinary = false
			break
		}
	}
	if allBinary {
		result := make([]bool, len(cleaned))
		for i := range len(cleaned) {
			result[i] = cleaned[i] == '1'
		}
		return result, nil
	}

	parts := strings.Split(cleaned, ",")
	result := make([]bool, 0, len(parts))
	for _, part := range parts {
		token := strings.ToLower(strings.TrimSpace(part))
		if token == "" {
			continue
		}
		switch token {
		case "1", "true", "t":
			result = append(result, true)
		case "0", "false", "f":
			result = append(result, false)
		default:
			return nil, fmt.Errorf("%w: unrecognized boolean token %q", ErrInvalidBitString, token)
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("%w: must not be empty", ErrInvalidBitString)
	}
	return result, nil
}

// FormatBits formats a boolean slice as a "0"/"1" bit string.
func FormatBits(bits []bool) string {
	var b strings.Builder
	b.Grow(len(bits))
	for _, bit := range bits {
		if bit {
			b.WriteByte('1')
		} else {
			b.WriteByte('0')
		}
	}
	return b.String()
}

// SerializeOption configures optional behavior of Serialize and Cipher.Serialize.
type SerializeOption func(*serializeConfig)

type serializeConfig struct {
	minSize int
}

// WithMinSize overrides the chunk split threshold minSize (2..50, default 10) for Serialize.
func WithMinSize(minSize int) SerializeOption {
	return func(cfg *serializeConfig) {
		cfg.minSize = minSize
	}
}

func resolveSerializeConfig(opts []SerializeOption) serializeConfig {
	cfg := serializeConfig{minSize: DefaultChunkMin}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

// DeriveOption configures optional behavior of DeriveSalt and NewCipherFromPassword.
type DeriveOption func(*deriveConfig)

type deriveConfig struct {
	hasContext bool
	context    []byte
	numBytes   int
	n          int
	r          int
	p          int
	maxMem     int
}

func coerceKDFInput[S Salt](val S) []byte {
	switch v := any(val).(type) {
	case string:
		return []byte(v)
	case []byte:
		return bytes.Clone(v)
	default:
		rv := reflect.ValueOf(val)
		if rv.Kind() == reflect.String {
			return []byte(rv.String())
		}
		return bytes.Clone(rv.Bytes())
	}
}

// WithContext binds an optional domain-separation context string or byte slice
// to scrypt key derivation. Passing an empty context returns ErrEmptyContext.
func WithContext[S Salt](context S) DeriveOption {
	raw := coerceKDFInput(context)
	return func(cfg *deriveConfig) {
		cfg.hasContext = true
		cfg.context = raw
	}
}

// WithNumBytes sets the derived hex salt byte length (must be >= MinSaltBytes = 16).
func WithNumBytes(numBytes int) DeriveOption {
	return func(cfg *deriveConfig) {
		cfg.numBytes = numBytes
	}
}

// WithScryptParams overrides the RFC 7914 scrypt cost parameters (n, r, p).
func WithScryptParams(n, r, p int) DeriveOption {
	return func(cfg *deriveConfig) {
		cfg.n = n
		cfg.r = r
		cfg.p = p
	}
}

// WithScryptMaxMem overrides the memory limit in bytes for scrypt (0 disables the cap).
func WithScryptMaxMem(maxMem int) DeriveOption {
	return func(cfg *deriveConfig) {
		cfg.maxMem = maxMem
	}
}

// DeriveSalt stretches a password or passphrase into a hex-encoded b53 salt
// using scrypt (RFC 7914). Password and context strings are encoded verbatim
// as UTF-8 without trimming or hex decoding.
func DeriveSalt[S Salt](password S, opts ...DeriveOption) (string, error) {
	pwBytes := coerceKDFInput(password)
	if len(pwBytes) == 0 {
		return "", ErrEmptyPassword
	}

	cfg := deriveConfig{
		numBytes: DefaultSaltBytes,
		n:        DefaultScryptN,
		r:        DefaultScryptR,
		p:        DefaultScryptP,
		maxMem:   DefaultScryptMaxMem,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	if cfg.hasContext && len(cfg.context) == 0 {
		return "", ErrEmptyContext
	}
	if cfg.numBytes < MinSaltBytes {
		return "", fmt.Errorf("%w: got %d", ErrSaltTooShort, cfg.numBytes)
	}

	var scryptSalt []byte
	if !cfg.hasContext {
		scryptSalt = []byte("b53:scrypt:v1")
	} else {
		scryptSalt = make([]byte, 0, len("b53:scrypt:v1:")+len(cfg.context))
		scryptSalt = append(scryptSalt, "b53:scrypt:v1:"...)
		scryptSalt = append(scryptSalt, cfg.context...)
	}

	derived, err := scryptKey(pwBytes, scryptSalt, cfg.n, cfg.r, cfg.p, cfg.maxMem, cfg.numBytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(derived), nil
}

// Encrypt encrypts 1..50 booleans with hidden length and random nonce into an
// IEEE 754 float64 in [0.0, 1.0).
func Encrypt[S Salt](bits []bool, salt S) (float64, error) {
	keyBytes, err := normalizeSalt(salt)
	if err != nil {
		return 0, err
	}
	return encryptWithKey(bits, keyBytes)
}

// Decrypt recovers the original boolean slice and its hidden length from an
// encrypted float64 in [0.0, 1.0) and the secret salt.
func Decrypt[S Salt](doubleVal float64, salt S) ([]bool, error) {
	keyBytes, err := normalizeSalt(salt)
	if err != nil {
		return nil, err
	}
	return decryptWithKey(doubleVal, keyBytes)
}

// Serialize splits an arbitrary-length boolean slice into (len(bits)/minSize)+1
// sequential chunks (or 0 if empty) of random lengths in [1, minSize] (first
// chunk strictly shorter than minSize) and encrypts them with chained per-chunk salts.
func Serialize[S Salt](bits []bool, salt S, opts ...SerializeOption) ([]float64, error) {
	keyBytes, err := normalizeSalt(salt)
	if err != nil {
		return nil, err
	}
	cfg := resolveSerializeConfig(opts)
	return serializeWithKey(bits, keyBytes, cfg.minSize)
}

// Deserialize verifies and restores a full boolean slice from chained float64 values.
func Deserialize[S Salt](values []float64, salt S) ([]bool, error) {
	keyBytes, err := normalizeSalt(salt)
	if err != nil {
		return nil, err
	}
	return deserializeWithKey(values, keyBytes)
}

// Cipher is a reusable, goroutine-safe cipher bound to a normalized secret salt.
type Cipher struct {
	keyBytes []byte
}

// NewCipher creates a Cipher bound to the given salt (hex string, UTF-8
// passphrase, or raw key bytes).
func NewCipher[S Salt](salt S) (*Cipher, error) {
	keyBytes, err := normalizeSalt(salt)
	if err != nil {
		return nil, err
	}
	return &Cipher{keyBytes: keyBytes}, nil
}

// NewCipherFromPassword stretches password with scrypt via DeriveSalt and returns
// a ready-to-use Cipher.
func NewCipherFromPassword[S Salt](password S, opts ...DeriveOption) (*Cipher, error) {
	salt, err := DeriveSalt(password, opts...)
	if err != nil {
		return nil, err
	}
	return NewCipher(salt)
}

// GenerateCipher generates a new random salt of numBytes bytes and returns a
// Cipher bound to it alongside the hex-encoded salt.
func GenerateCipher(numBytes int) (*Cipher, string, error) {
	salt, err := GenerateSalt(numBytes)
	if err != nil {
		return nil, "", err
	}
	cipher, err := NewCipher(salt)
	if err != nil {
		return nil, "", err
	}
	return cipher, salt, nil
}

func (c *Cipher) checkReady() error {
	if c == nil {
		return ErrNilCipher
	}
	if len(c.keyBytes) == 0 {
		return ErrEmptySalt
	}
	return nil
}

// KeyLen returns the length in bytes of the normalized secret key.
func (c *Cipher) KeyLen() int {
	if c == nil {
		return 0
	}
	return len(c.keyBytes)
}

// String implements fmt.Stringer without exposing secret key material.
func (c *Cipher) String() string {
	if c == nil {
		return "Cipher(<nil>)"
	}
	return fmt.Sprintf("Cipher(key_bytes=%d)", len(c.keyBytes))
}

// GoString implements fmt.GoStringer without exposing secret key material.
func (c *Cipher) GoString() string {
	if c == nil {
		return "(*b53.Cipher)(nil)"
	}
	return fmt.Sprintf("b53.Cipher{keyBytes:<redacted len=%d>}", len(c.keyBytes))
}

// Encrypt encrypts 1..50 booleans into a float64 in [0.0, 1.0).
func (c *Cipher) Encrypt(bits []bool) (float64, error) {
	if err := c.checkReady(); err != nil {
		return 0, err
	}
	return encryptWithKey(bits, c.keyBytes)
}

// Decrypt decrypts a float64 in [0.0, 1.0) back into the original boolean slice.
func (c *Cipher) Decrypt(doubleVal float64) ([]bool, error) {
	if err := c.checkReady(); err != nil {
		return nil, err
	}
	return decryptWithKey(doubleVal, c.keyBytes)
}

// Serialize splits an arbitrary-length boolean slice into chained float64 values.
func (c *Cipher) Serialize(bits []bool, opts ...SerializeOption) ([]float64, error) {
	if err := c.checkReady(); err != nil {
		return nil, err
	}
	cfg := resolveSerializeConfig(opts)
	return serializeWithKey(bits, c.keyBytes, cfg.minSize)
}

// Deserialize verifies and restores a full boolean slice from chained float64 values.
func (c *Cipher) Deserialize(values []float64) ([]bool, error) {
	if err := c.checkReady(); err != nil {
		return nil, err
	}
	return deserializeWithKey(values, c.keyBytes)
}

// EncryptString parses a bit string (e.g. "10110" or "true,false,true") and encrypts it.
func (c *Cipher) EncryptString(rawBits string) (float64, error) {
	if err := c.checkReady(); err != nil {
		return 0, err
	}
	bits, err := ParseBits(rawBits)
	if err != nil {
		return 0, err
	}
	return encryptWithKey(bits, c.keyBytes)
}

// DecryptString decrypts a float64 and formats the recovered booleans as a "0"/"1" bit string.
func (c *Cipher) DecryptString(doubleVal float64) (string, error) {
	bits, err := c.Decrypt(doubleVal)
	if err != nil {
		return "", err
	}
	return FormatBits(bits), nil
}
