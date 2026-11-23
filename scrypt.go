package b53

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/bits"
)

const maxGoInt = int(^uint(0) >> 1)

// scryptKey derives a key of length dkLen using RFC 7914 scrypt with HMAC-SHA256
// and enforces an optional memory limit maxMem (when maxMem > 0).
func scryptKey(password, salt []byte, n, r, p, maxMem, dkLen int) ([]byte, error) {
	if n < 2 || (n&(n-1)) != 0 {
		return nil, fmt.Errorf("%w: n must be a power of 2 >= 2, got %d", ErrInvalidScryptParam, n)
	}
	if r < 1 {
		return nil, fmt.Errorf("%w: r must be >= 1, got %d", ErrInvalidScryptParam, r)
	}
	if p < 1 {
		return nil, fmt.Errorf("%w: p must be >= 1, got %d", ErrInvalidScryptParam, p)
	}
	if maxMem < 0 {
		return nil, fmt.Errorf("%w: maxmem must be >= 0, got %d", ErrInvalidScryptParam, maxMem)
	}
	if dkLen < 1 {
		return nil, fmt.Errorf("%w: dkLen must be >= 1, got %d", ErrInvalidScryptParam, dkLen)
	}

	// RFC 7914 bounds: r*p < 2^30 and no integer overflow in buffer sizes.
	if uint64(r) > (1<<30-1)/uint64(p) {
		return nil, fmt.Errorf("%w: r * p exceeds RFC 7914 limit", ErrInvalidScryptParam)
	}
	if uint64(r) > uint64(maxGoInt)/(128*uint64(p)) || uint64(r) > uint64(maxGoInt)/(32*uint64(n)) {
		return nil, fmt.Errorf("%w: scrypt buffer size overflow", ErrInvalidScryptParam)
	}

	// OpenSSL-compatible memory estimate: 128 * r * (N + p + 2) bytes.
	// Check overflow before computing memNeeded.
	sumNP := uint64(n) + uint64(p) + 2
	if uint64(r) > (^uint64(0))/128 || sumNP > (^uint64(0))/(128*uint64(r)) {
		return nil, fmt.Errorf("%w: memory requirement overflow", ErrScryptMemoryLimit)
	}
	memNeeded := 128 * uint64(r) * sumNP
	if maxMem > 0 && memNeeded > uint64(maxMem) {
		return nil, fmt.Errorf(
			"%w: required %d bytes exceeds maxmem %d",
			ErrScryptMemoryLimit,
			memNeeded,
			maxMem,
		)
	}

	b := pbkdf2HMACSHA256(password, salt, 1, p*128*r)
	xy := make([]uint32, 64*r)
	v := make([]uint32, 32*r*n)
	for i := range p {
		smix(b[i*128*r:(i+1)*128*r], r, n, v, xy)
	}
	return pbkdf2HMACSHA256(password, b, 1, dkLen), nil
}

func pbkdf2HMACSHA256(password, salt []byte, iter, keyLen int) []byte {
	const hashLen = sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	dk := make([]byte, 0, numBlocks*hashLen)

	var blockBuf [4]byte
	var uBuf [hashLen]byte
	var tBuf [hashLen]byte
	mac := hmac.New(sha256.New, password)

	for block := 1; block <= numBlocks; block++ {
		mac.Reset()
		mac.Write(salt)
		binary.BigEndian.PutUint32(blockBuf[:], uint32(block))
		mac.Write(blockBuf[:])
		u := mac.Sum(uBuf[:0])
		copy(tBuf[:], u)

		for range iter - 1 {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(uBuf[:0])
			for j := range hashLen {
				tBuf[j] ^= u[j]
			}
		}
		dk = append(dk, tBuf[:]...)
	}
	return dk[:keyLen]
}

func salsaXOR(tmp *[16]uint32, in, out []uint32) {
	w0 := tmp[0] ^ in[0]
	w1 := tmp[1] ^ in[1]
	w2 := tmp[2] ^ in[2]
	w3 := tmp[3] ^ in[3]
	w4 := tmp[4] ^ in[4]
	w5 := tmp[5] ^ in[5]
	w6 := tmp[6] ^ in[6]
	w7 := tmp[7] ^ in[7]
	w8 := tmp[8] ^ in[8]
	w9 := tmp[9] ^ in[9]
	w10 := tmp[10] ^ in[10]
	w11 := tmp[11] ^ in[11]
	w12 := tmp[12] ^ in[12]
	w13 := tmp[13] ^ in[13]
	w14 := tmp[14] ^ in[14]
	w15 := tmp[15] ^ in[15]

	x0, x1, x2, x3, x4, x5, x6, x7, x8 := w0, w1, w2, w3, w4, w5, w6, w7, w8
	x9, x10, x11, x12, x13, x14, x15 := w9, w10, w11, w12, w13, w14, w15

	for range 4 {
		x4 ^= bits.RotateLeft32(x0+x12, 7)
		x8 ^= bits.RotateLeft32(x4+x0, 9)
		x12 ^= bits.RotateLeft32(x8+x4, 13)
		x0 ^= bits.RotateLeft32(x12+x8, 18)

		x9 ^= bits.RotateLeft32(x5+x1, 7)
		x13 ^= bits.RotateLeft32(x9+x5, 9)
		x1 ^= bits.RotateLeft32(x13+x9, 13)
		x5 ^= bits.RotateLeft32(x1+x13, 18)

		x14 ^= bits.RotateLeft32(x10+x6, 7)
		x2 ^= bits.RotateLeft32(x14+x10, 9)
		x6 ^= bits.RotateLeft32(x2+x14, 13)
		x10 ^= bits.RotateLeft32(x6+x2, 18)

		x3 ^= bits.RotateLeft32(x15+x11, 7)
		x7 ^= bits.RotateLeft32(x3+x15, 9)
		x11 ^= bits.RotateLeft32(x7+x3, 13)
		x15 ^= bits.RotateLeft32(x11+x7, 18)

		x1 ^= bits.RotateLeft32(x0+x3, 7)
		x2 ^= bits.RotateLeft32(x1+x0, 9)
		x3 ^= bits.RotateLeft32(x2+x1, 13)
		x0 ^= bits.RotateLeft32(x3+x2, 18)

		x6 ^= bits.RotateLeft32(x5+x4, 7)
		x7 ^= bits.RotateLeft32(x6+x5, 9)
		x4 ^= bits.RotateLeft32(x7+x6, 13)
		x5 ^= bits.RotateLeft32(x4+x7, 18)

		x11 ^= bits.RotateLeft32(x10+x9, 7)
		x8 ^= bits.RotateLeft32(x11+x10, 9)
		x9 ^= bits.RotateLeft32(x8+x11, 13)
		x10 ^= bits.RotateLeft32(x9+x8, 18)

		x12 ^= bits.RotateLeft32(x15+x14, 7)
		x13 ^= bits.RotateLeft32(x12+x15, 9)
		x14 ^= bits.RotateLeft32(x13+x12, 13)
		x15 ^= bits.RotateLeft32(x14+x13, 18)
	}

	x0 += w0
	x1 += w1
	x2 += w2
	x3 += w3
	x4 += w4
	x5 += w5
	x6 += w6
	x7 += w7
	x8 += w8
	x9 += w9
	x10 += w10
	x11 += w11
	x12 += w12
	x13 += w13
	x14 += w14
	x15 += w15

	out[0], tmp[0] = x0, x0
	out[1], tmp[1] = x1, x1
	out[2], tmp[2] = x2, x2
	out[3], tmp[3] = x3, x3
	out[4], tmp[4] = x4, x4
	out[5], tmp[5] = x5, x5
	out[6], tmp[6] = x6, x6
	out[7], tmp[7] = x7, x7
	out[8], tmp[8] = x8, x8
	out[9], tmp[9] = x9, x9
	out[10], tmp[10] = x10, x10
	out[11], tmp[11] = x11, x11
	out[12], tmp[12] = x12, x12
	out[13], tmp[13] = x13, x13
	out[14], tmp[14] = x14, x14
	out[15], tmp[15] = x15, x15
}

func blockMix(tmp *[16]uint32, in, out []uint32, r int) {
	copy(tmp[:], in[(2*r-1)*16:2*r*16])
	for i := 0; i < 2*r; i += 2 {
		salsaXOR(tmp, in[i*16:], out[(i/2)*16:])
		salsaXOR(tmp, in[(i+1)*16:], out[(r+i/2)*16:])
	}
}

func blockXOR(dst, src []uint32, n int) {
	for i, v := range src[:n] {
		dst[i] ^= v
	}
}

func integerify(x []uint32, r int) uint64 {
	last := (2*r - 1) * 16
	return uint64(x[last]) | (uint64(x[last+1]) << 32)
}

func smix(b []byte, r, n int, v, xy []uint32) {
	var tmp [16]uint32
	x := xy[:32*r]
	y := xy[32*r:]

	j := 0
	for i := range 32 * r {
		x[i] = binary.LittleEndian.Uint32(b[j:])
		j += 4
	}
	for i := 0; i < n; i += 2 {
		copy(v[i*32*r:], x)
		blockMix(&tmp, x, y, r)

		copy(v[(i+1)*32*r:], y)
		blockMix(&tmp, y, x, r)
	}
	mask := uint64(n) - 1
	for i := 0; i < n; i += 2 {
		idx := int(integerify(x, r) & mask)
		blockXOR(x, v[idx*32*r:], 32*r)
		blockMix(&tmp, x, y, r)

		idx = int(integerify(y, r) & mask)
		blockXOR(y, v[idx*32*r:], 32*r)
		blockMix(&tmp, y, x, r)
	}
	j = 0
	for _, val := range x {
		binary.LittleEndian.PutUint32(b[j:], val)
		j += 4
	}
}
