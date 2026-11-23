// Package b53a implements the asymmetric X25519 + HKDF-SHA256 extension for b53.
//
// It provides both one-way sealed sessions (using ephemeral X25519 keys where
// only the recipient's public key is needed to encrypt) and pairwise X25519
// key agreement without embedding key material inside the output float64 values.
package b53a

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/1orgar/b53-go"
)

// X25519KeyBytes is the byte length of raw X25519 keys and derived session keys.
const X25519KeyBytes = 32

var (
	// ErrInvalidKey indicates a missing, malformed, or wrong-length X25519 key.
	ErrInvalidKey = errors.New("b53a: invalid X25519 key")

	// ErrLowOrderPoint indicates an X25519 exchange producing an all-zero shared secret.
	ErrLowOrderPoint = errors.New("b53a: invalid X25519 key exchange (low-order public point)")

	// ErrEmptyContext indicates an explicitly provided empty HKDF context.
	ErrEmptyContext = b53.ErrEmptyContext

	zeroKey [X25519KeyBytes]byte
)

// PrivateKey constrains accepted X25519 private key inputs:
// a 64-character hex string, a 32-byte slice, or *ecdh.PrivateKey.
type PrivateKey interface {
	~string | ~[]byte | *ecdh.PrivateKey
}

// PublicKey constrains accepted X25519 public key inputs:
// a 64-character hex string, a 32-byte slice, or *ecdh.PublicKey.
type PublicKey interface {
	~string | ~[]byte | *ecdh.PublicKey
}

// Cipher is an alias for b53.Cipher bound to an X25519-derived secret key.
type Cipher = b53.Cipher

// KeyPair holds a hex-encoded X25519 private/public key pair.
type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

// String implements fmt.Stringer without exposing the private key.
func (k KeyPair) String() string {
	return fmt.Sprintf("KeyPair(public_key=%q, private_key='<redacted>')", k.PublicKey)
}

// GoString implements fmt.GoStringer without exposing the private key.
func (k KeyPair) GoString() string {
	return fmt.Sprintf("b53a.KeyPair{PublicKey:%q, PrivateKey:\"<redacted>\"}", k.PublicKey)
}

// Option configures optional parameters for b53a operations.
type Option func(*options)

type options struct {
	hasContext bool
	context    []byte
	minSize    int
}

func defaultOptions(opts []Option) options {
	cfg := options{minSize: b53.DefaultChunkMin}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

// WithContext binds an optional domain-separation context string or byte slice
// into HKDF-SHA256 key derivation. Passing an empty context returns ErrEmptyContext.
func WithContext[S b53.Salt](context S) Option {
	raw := coerceContextBytes(context)
	return func(cfg *options) {
		cfg.hasContext = true
		cfg.context = raw
	}
}

// WithMinSize overrides the chunk split threshold (2..50, default 10) for
// Serialize and SerializeSealed.
func WithMinSize(minSize int) Option {
	return func(cfg *options) {
		cfg.minSize = minSize
	}
}

func coerceContextBytes[S b53.Salt](val S) []byte {
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

func buildInfo(prefix string, cfg options) ([]byte, error) {
	if !cfg.hasContext {
		return []byte(prefix), nil
	}
	if len(cfg.context) == 0 {
		return nil, ErrEmptyContext
	}
	out := make([]byte, 0, len(prefix)+1+len(cfg.context))
	out = append(out, prefix...)
	out = append(out, ':')
	out = append(out, cfg.context...)
	return out, nil
}

func decodeKeyBytes(rawInput any, label string) ([]byte, error) {
	var raw []byte
	switch v := rawInput.(type) {
	case string:
		decoded, err := decodeHexString(v, label)
		if err != nil {
			return nil, err
		}
		raw = decoded
	case []byte:
		raw = v
	default:
		rv := reflect.ValueOf(rawInput)
		if rv.Kind() == reflect.String {
			decoded, err := decodeHexString(rv.String(), label)
			if err != nil {
				return nil, err
			}
			raw = decoded
		} else {
			raw = rv.Bytes()
		}
	}

	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: %s must not be empty", ErrInvalidKey, label)
	}
	if len(raw) != X25519KeyBytes {
		return nil, fmt.Errorf("%w: %s must be %d bytes, got %d", ErrInvalidKey, label, X25519KeyBytes, len(raw))
	}
	return raw, nil
}

func decodeHexString(s, label string) ([]byte, error) {
	cleaned := strings.TrimSpace(s)
	if cleaned == "" {
		return nil, fmt.Errorf("%w: %s must not be empty", ErrInvalidKey, label)
	}
	decoded, ok := decodePythonHex(cleaned)
	if !ok {
		return nil, fmt.Errorf("%w: %s must be a 64-character hex string or 32 raw bytes", ErrInvalidKey, label)
	}
	return decoded, nil
}

func decodePythonHex(s string) ([]byte, bool) {
	out := make([]byte, 0, len(s)/2)
	for i := 0; i < len(s); {
		b := s[i]
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\x0b' || b == '\x0c' {
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

func loadPrivateKey[K PrivateKey](key K) (*ecdh.PrivateKey, error) {
	if pk, ok := any(key).(*ecdh.PrivateKey); ok {
		if pk == nil || pk.Curve() != ecdh.X25519() {
			return nil, fmt.Errorf("%w: expected non-nil X25519 private key", ErrInvalidKey)
		}
		return pk, nil
	}
	raw, err := decodeKeyBytes(key, "private_key")
	if err != nil {
		return nil, err
	}
	pk, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	return pk, nil
}

func loadPublicKey[K PublicKey](key K) (*ecdh.PublicKey, error) {
	if pk, ok := any(key).(*ecdh.PublicKey); ok {
		if pk == nil || pk.Curve() != ecdh.X25519() {
			return nil, fmt.Errorf("%w: expected non-nil X25519 public key", ErrInvalidKey)
		}
		return pk, nil
	}
	raw, err := decodeKeyBytes(key, "public_key")
	if err != nil {
		return nil, err
	}
	pk, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	return pk, nil
}

func exchangeX25519(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLowOrderPoint, err)
	}
	if len(shared) != X25519KeyBytes || subtle.ConstantTimeCompare(shared, zeroKey[:]) == 1 {
		return nil, ErrLowOrderPoint
	}
	return shared, nil
}

func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	extract := hmac.New(sha256.New, salt)
	extract.Write(ikm)
	prk := extract.Sum(nil)

	okm := make([]byte, 0, length)
	var t []byte
	for counter := byte(1); len(okm) < length; counter++ {
		expand := hmac.New(sha256.New, prk)
		expand.Write(t)
		expand.Write(info)
		expand.Write([]byte{counter})
		t = expand.Sum(nil)
		okm = append(okm, t...)
	}
	return okm[:length]
}

// GenerateKeyPair generates a new X25519 key pair encoded as 64-character hex strings.
func GenerateKeyPair() (KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("b53a: failed to generate X25519 key pair: %w", err)
	}
	return KeyPair{
		PrivateKey: hex.EncodeToString(priv.Bytes()),
		PublicKey:  hex.EncodeToString(priv.PublicKey().Bytes()),
	}, nil
}

// PublicKeyFromPrivate derives the 64-character hex X25519 public key corresponding
// to privateKey.
func PublicKeyFromPrivate[K PrivateKey](privateKey K) (string, error) {
	priv, err := loadPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(priv.PublicKey().Bytes()), nil
}

func deriveSessionCipher(shared, ephPubBytes, recvPubBytes, info []byte) (*b53.Cipher, error) {
	salt := make([]byte, 0, X25519KeyBytes*2)
	salt = append(salt, ephPubBytes...)
	salt = append(salt, recvPubBytes...)
	sessionKey := hkdfSHA256(shared, salt, info, X25519KeyBytes)
	return b53.NewCipher(sessionKey)
}

// SealSession creates a one-way asymmetric session from recipientPublicKey.
// Returns (cipher, capsuleHex, nil). Only the holder of the matching private key
// can reopen the session via OpenSession.
func SealSession[Pub PublicKey](recipientPublicKey Pub, opts ...Option) (*b53.Cipher, string, error) {
	cfg := defaultOptions(opts)
	recvPub, err := loadPublicKey(recipientPublicKey)
	if err != nil {
		return nil, "", err
	}
	info, err := buildInfo("b53a:session:v1", cfg)
	if err != nil {
		return nil, "", err
	}

	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("b53a: failed to generate ephemeral key: %w", err)
	}
	shared, err := exchangeX25519(ephPriv, recvPub)
	if err != nil {
		return nil, "", err
	}

	ephPubBytes := ephPriv.PublicKey().Bytes()
	cipher, err := deriveSessionCipher(shared, ephPubBytes, recvPub.Bytes(), info)
	if err != nil {
		return nil, "", err
	}
	return cipher, hex.EncodeToString(ephPubBytes), nil
}

// OpenSession reopens an asymmetric session created by SealSession using capsule
// and recipientPrivateKey.
func OpenSession[Cap PublicKey, Priv PrivateKey](capsule Cap, recipientPrivateKey Priv, opts ...Option) (*b53.Cipher, error) {
	cfg := defaultOptions(opts)
	ephPub, err := loadPublicKey(capsule)
	if err != nil {
		return nil, err
	}
	recvPriv, err := loadPrivateKey(recipientPrivateKey)
	if err != nil {
		return nil, err
	}
	info, err := buildInfo("b53a:session:v1", cfg)
	if err != nil {
		return nil, err
	}

	shared, err := exchangeX25519(recvPriv, ephPub)
	if err != nil {
		return nil, err
	}
	return deriveSessionCipher(shared, ephPub.Bytes(), recvPriv.PublicKey().Bytes(), info)
}

// EncryptSealed encrypts 1..50 booleans into (doubleVal, capsuleHex) using only
// recipientPublicKey.
func EncryptSealed[Pub PublicKey](bits []bool, recipientPublicKey Pub, opts ...Option) (float64, string, error) {
	cipher, capsule, err := SealSession(recipientPublicKey, opts...)
	if err != nil {
		return 0, "", err
	}
	encoded, err := cipher.Encrypt(bits)
	if err != nil {
		return 0, "", err
	}
	return encoded, capsule, nil
}

// DecryptSealed decrypts (doubleVal, capsule) using recipientPrivateKey.
func DecryptSealed[Cap PublicKey, Priv PrivateKey](doubleVal float64, capsule Cap, recipientPrivateKey Priv, opts ...Option) ([]bool, error) {
	cipher, err := OpenSession(capsule, recipientPrivateKey, opts...)
	if err != nil {
		return nil, err
	}
	return cipher.Decrypt(doubleVal)
}

// SerializeSealed serializes an arbitrary-length boolean slice into
// (doubles, capsuleHex) using only recipientPublicKey.
func SerializeSealed[Pub PublicKey](bits []bool, recipientPublicKey Pub, opts ...Option) ([]float64, string, error) {
	cfg := defaultOptions(opts)
	cipher, capsule, err := SealSession(recipientPublicKey, opts...)
	if err != nil {
		return nil, "", err
	}
	doubles, err := cipher.Serialize(bits, b53.WithMinSize(cfg.minSize))
	if err != nil {
		return nil, "", err
	}
	return doubles, capsule, nil
}

// DeserializeSealed deserializes (values, capsule) using recipientPrivateKey.
func DeserializeSealed[Cap PublicKey, Priv PrivateKey](values []float64, capsule Cap, recipientPrivateKey Priv, opts ...Option) ([]bool, error) {
	cipher, err := OpenSession(capsule, recipientPrivateKey, opts...)
	if err != nil {
		return nil, err
	}
	return cipher.Deserialize(values)
}

// DeriveSharedSalt derives a deterministic 256-bit hex salt via pairwise
// X25519 + HKDF-SHA256 between privateKey and peerPublicKey.
func DeriveSharedSalt[Priv PrivateKey, Pub PublicKey](privateKey Priv, peerPublicKey Pub, opts ...Option) (string, error) {
	cfg := defaultOptions(opts)
	priv, err := loadPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	peerPub, err := loadPublicKey(peerPublicKey)
	if err != nil {
		return "", err
	}
	info, err := buildInfo("b53a:pairwise:v1", cfg)
	if err != nil {
		return "", err
	}

	shared, err := exchangeX25519(priv, peerPub)
	if err != nil {
		return "", err
	}

	first := priv.PublicKey().Bytes()
	second := peerPub.Bytes()
	if bytes.Compare(first, second) > 0 {
		first, second = second, first
	}
	salt := make([]byte, 0, X25519KeyBytes*2)
	salt = append(salt, first...)
	salt = append(salt, second...)

	derived := hkdfSHA256(shared, salt, info, X25519KeyBytes)
	return hex.EncodeToString(derived), nil
}

// NewCipher creates a reusable Cipher bound to a pairwise X25519-derived salt.
func NewCipher[Priv PrivateKey, Pub PublicKey](privateKey Priv, peerPublicKey Pub, opts ...Option) (*b53.Cipher, error) {
	salt, err := DeriveSharedSalt(privateKey, peerPublicKey, opts...)
	if err != nil {
		return nil, err
	}
	return b53.NewCipher(salt)
}

// Encrypt encrypts 1..50 booleans into one float64 using pairwise X25519 key agreement.
func Encrypt[Priv PrivateKey, Pub PublicKey](bits []bool, privateKey Priv, peerPublicKey Pub, opts ...Option) (float64, error) {
	salt, err := DeriveSharedSalt(privateKey, peerPublicKey, opts...)
	if err != nil {
		return 0, err
	}
	return b53.Encrypt(bits, salt)
}

// Decrypt decrypts one float64 using pairwise X25519 key agreement.
func Decrypt[Priv PrivateKey, Pub PublicKey](doubleVal float64, privateKey Priv, peerPublicKey Pub, opts ...Option) ([]bool, error) {
	salt, err := DeriveSharedSalt(privateKey, peerPublicKey, opts...)
	if err != nil {
		return nil, err
	}
	return b53.Decrypt(doubleVal, salt)
}

// Serialize serializes arbitrary-length booleans into chained float64 values
// using pairwise X25519 key agreement.
func Serialize[Priv PrivateKey, Pub PublicKey](bits []bool, privateKey Priv, peerPublicKey Pub, opts ...Option) ([]float64, error) {
	cfg := defaultOptions(opts)
	salt, err := DeriveSharedSalt(privateKey, peerPublicKey, opts...)
	if err != nil {
		return nil, err
	}
	return b53.Serialize(bits, salt, b53.WithMinSize(cfg.minSize))
}

// Deserialize deserializes chained float64 values using pairwise X25519 key agreement.
func Deserialize[Priv PrivateKey, Pub PublicKey](values []float64, privateKey Priv, peerPublicKey Pub, opts ...Option) ([]bool, error) {
	salt, err := DeriveSharedSalt(privateKey, peerPublicKey, opts...)
	if err != nil {
		return nil, err
	}
	return b53.Deserialize(values, salt)
}
