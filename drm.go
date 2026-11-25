// Package edgetts implements the minimum Microsoft Edge read-aloud protocol
// needed to turn text into MP3 audio. It is a self-contained port of the
// algorithm described in rany2/edge-tts (MIT); no external TTS service is used.
//
// Module: github.com/afeiship/go-edgetts
//
// Sec-MS-GEC v2 token generation is a port of upstream drm.py. The digest is
// deliberately NOT standard SHA-256 (the schedule and round constants are
// perturbed), so crypto/sha256 cannot be used here.
package edgetts

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
)

const (
	trustedClientToken    = "6A5AA1D4EAFF4E9FB37E23D68491D6F4"
	secMSGECStrictVersion = "2-143.0.3650.75"
	windowsFileTimeEpoch  = 11644473600
	u32Mask               = uint32(0xFFFFFFFF)
	sha256Adjustment      = uint32(0xC9DC06A7)
	sigma0Adjustment      = uint32(0x059C0B80)
	sigma1Adjustment      = uint32(0x000B92C0)
	cs64Factor            = uint32(0x82893933)
	cs64Adjustment0       = uint32(0xF2F90B1A)
	cs64Adjustment1       = uint32(0x0B1A0000)
)

var roundConstants = [64]uint32{
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
	0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
	0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
	0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
	0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
	0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
	0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
	0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
	0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
}

var initialSchedule = [14]uint32{
	0xEB24BF9E, 0x1558691F, 0xA0C09EE2, 0x0CFA32BA,
	0xA622EE8C, 0xD1DD9491, 0xC0DD25A0, 0xF9E70AB6,
	0xF0C31573, 0x7058CE4E, 0x7188E606, 0x00E5AB33,
	0xD258B060, 0x72766564,
}

var cs64Coefficients = [14][2]uint32{
	{0xE82E91B1, 0xB32700D0},
	{0x44DE24C6, 0x88DFF51D},
	{0x3BEB65BC, 0x29514038},
	{0xC89C5933, 0xB328CBDF},
	{0x8D1EC211, 0xD405B4D5},
	{0x314EF5D5, 0x26E55F3C},
	{0xE92491B1, 0x607801C6},
	{0xF0A5B9D5, 0x82B2C1FB},
	{0x06064CF3, 0xFA51A3DA},
	{0xDA79FA60, 0x207CC464},
	{0xBED20560, 0x3C3C74F3},
	{0x89F9C9F8, 0xD2D14B61},
	{0x35FA38C6, 0xBB04A2C1},
	{0xCB49E3C6, 0xC5626167},
}

var (
	initialState = shaState{0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19}
	seedState    = shaState{0xFD9FBEA2, 0x91243CE7, 0xBE499094, 0xCD2E1E0A, 0x6C006F49, 0x04BD35AB, 0xFEB0A7E4, 0x03EFFBD2}
)

type shaState [8]uint32

func rotate16(v uint32) uint32 { return (v << 16) | (v >> 16) }

// bigEndianTail reads up to four bytes right-aligned, like int.from_bytes(..., "big").
func bigEndianTail(b []byte) uint32 {
	var v uint32
	for _, c := range b {
		v = (v << 8) | uint32(c)
	}
	return v
}

func sigma0(v uint32) uint32 {
	x := uint64(v)
	return uint32(((x >> 7) ^ (x << 25) ^ (x >> 18) ^ (x << 14) ^ (x >> 3)) & uint64(u32Mask))
}

func sigma1(v uint32) uint32 {
	x := uint64(v)
	return uint32(((x >> 17) ^ (x << 15) ^ (x >> 19) ^ (x << 13) ^ (x >> 10)) & uint64(u32Mask))
}

// Multiplying a 32-bit word by 2^32+1 repeats it across 64 bits, so a right
// shift produces the ROTR low bits exactly as in the Python implementation.
func bigSigma1(e uint32) uint64 {
	v := uint64(e) * 0x100000001
	return (v >> 6) ^ (v >> 11) ^ (v >> 25)
}

func bigSigma0(a uint32) uint64 {
	v := uint64(a) * 0x100000001
	return (v >> 2) ^ (v >> 13) ^ (v >> 22)
}

func blockConstants(firstRound int) []uint32 {
	if firstRound != 14 {
		return roundConstants[:]
	}
	out := roundConstants
	out[14] = sha256Adjustment
	return out[:]
}

func shaRounds(state shaState, words []uint32, firstRound int) shaState {
	a, b, c, d, e, f, g, h := state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]
	constants := blockConstants(firstRound)
	mask := uint64(u32Mask)

	aligned := 64
	if v := ((firstRound + 7) / 8) * 8; v < aligned {
		aligned = v
	}
	for i := firstRound; i < aligned; i++ {
		t1 := (uint64(h) + bigSigma1(e) + uint64(g^(e&(f^g))) + uint64(constants[i]) + uint64(words[i])) & mask
		t2 := (bigSigma0(a) + uint64((a&b)|(c&(a|b)))) & mask
		// Python assigns the tuple at once: e_new must read the old d.
		a, b, c, d, e, f, g, h = uint32((t1+t2)&mask), a, b, c, uint32((uint64(d)+t1)&mask), e, f, g
	}
	for i := aligned; i < 64; i += 8 {
		t1 := (uint64(h) + bigSigma1(e) + uint64(g^(e&(f^g))) + uint64(constants[i]) + uint64(words[i])) & mask
		d = uint32((uint64(d) + t1) & mask)
		h = uint32((t1 + bigSigma0(a) + uint64((a&b)|(c&(a|b)))) & mask)

		t1 = (uint64(g) + bigSigma1(d) + uint64(f^(d&(e^f))) + uint64(constants[i+1]) + uint64(words[i+1])) & mask
		c = uint32((uint64(c) + t1) & mask)
		g = uint32((t1 + bigSigma0(h) + uint64((h&a)|(b&(h|a)))) & mask)

		t1 = (uint64(f) + bigSigma1(c) + uint64(e^(c&(d^e))) + uint64(constants[i+2]) + uint64(words[i+2])) & mask
		b = uint32((uint64(b) + t1) & mask)
		f = uint32((t1 + bigSigma0(g) + uint64((g&h)|(a&(g|h)))) & mask)

		t1 = (uint64(e) + bigSigma1(b) + uint64(d^(b&(c^d))) + uint64(constants[i+3]) + uint64(words[i+3])) & mask
		a = uint32((uint64(a) + t1) & mask)
		e = uint32((t1 + bigSigma0(f) + uint64((f&g)|(h&(f|g)))) & mask)

		t1 = (uint64(d) + bigSigma1(a) + uint64(c^(a&(b^c))) + uint64(constants[i+4]) + uint64(words[i+4])) & mask
		h = uint32((uint64(h) + t1) & mask)
		d = uint32((t1 + bigSigma0(e) + uint64((e&f)|(g&(e|f)))) & mask)

		t1 = (uint64(c) + bigSigma1(h) + uint64(b^(h&(a^b))) + uint64(constants[i+5]) + uint64(words[i+5])) & mask
		g = uint32((uint64(g) + t1) & mask)
		c = uint32((t1 + bigSigma0(d) + uint64((d&e)|(f&(d|e)))) & mask)

		t1 = (uint64(b) + bigSigma1(g) + uint64(a^(g&(h^a))) + uint64(constants[i+6]) + uint64(words[i+6])) & mask
		f = uint32((uint64(f) + t1) & mask)
		b = uint32((t1 + bigSigma0(c) + uint64((c&d)|(e&(c|d)))) & mask)

		t1 = (uint64(a) + bigSigma1(f) + uint64(h^(f&(g^h))) + uint64(constants[i+7]) + uint64(words[i+7])) & mask
		e = uint32((uint64(e) + t1) & mask)
		a = uint32((t1 + bigSigma0(b) + uint64((b&c)|(d&(b|c)))) & mask)
	}
	return shaState{a, b, c, d, e, f, g, h}
}

func expandSchedule(words []uint32, from int) []uint32 {
	mask := uint64(u32Mask)
	for i := from; i < 64; i++ {
		x, y := uint64(words[i-2]), uint64(words[i-15])
		s1 := (x >> 17) ^ (x << 15) ^ (x >> 19) ^ (x << 13) ^ (x >> 10)
		s0 := (y >> 7) ^ (y << 25) ^ (y >> 18) ^ (y << 14) ^ (y >> 3)
		words = append(words, uint32((s1+uint64(words[i-7])+s0+uint64(words[i-16]))&mask))
	}
	return words
}

func initialHashState(data []byte) shaState {
	mask := uint64(u32Mask)
	words := make([]uint32, 0, 64)
	words = append(words, make([]uint32, 14)...)
	words = append(words, bigEndianTail(data[:3]), bigEndianTail(data[3:7]))
	for i := 16; i < 30; i++ {
		value := uint64(initialSchedule[i-16])
		if i-2 >= 14 {
			if i == 16 {
				value += uint64(sigma1(words[i-2]) ^ sigma1Adjustment)
			} else {
				value += uint64(sigma1(words[i-2]))
			}
		}
		if i-7 >= 14 {
			value += uint64(words[i-7])
		}
		if i-15 >= 14 {
			if i == 29 {
				value += uint64(sigma0(words[i-15]) ^ sigma0Adjustment)
			} else {
				value += uint64(sigma0(words[i-15]))
			}
		}
		words = append(words, uint32(value&mask))
	}
	words = append(words, uint32((uint64(sigma1(words[28]))+uint64(words[23])+uint64(sigma0(words[15]))+
		uint64(words[14])+uint64(sha256Adjustment)-uint64(roundConstants[14]))&mask))
	words = expandSchedule(words, 31)

	working := shaRounds(seedState, words, 14)
	var out shaState
	for i := range out {
		out[i] = uint32((uint64(initialState[i]) + uint64(working[i])) & mask)
	}
	return out
}

func modifiedSHA256(data []byte) ([]byte, error) {
	if len(data) < 7 {
		return nil, fmt.Errorf("token salt must be at least 7 bytes")
	}
	length := 57 + len(data)
	padded := make([]byte, 0, 128)
	padded = append(padded, data[7:]...)
	padded = append(padded, 0x80)
	// Python's % is Euclidean; Go's % keeps the dividend's sign.
	padding := (55 - length) % 64
	if padding < 0 {
		padding += 64
	}
	padded = append(padded, make([]byte, padding)...)
	var tail [8]byte
	binary.BigEndian.PutUint64(tail[:], uint64(length*8))
	padded = append(padded, tail[:]...)

	state := initialHashState(data[:7])
	for offset := 0; offset < len(padded); offset += 64 {
		words := make([]uint32, 0, 64)
		for i := 0; i < 16; i++ {
			words = append(words, binary.BigEndian.Uint32(padded[offset+i*4:offset+i*4+4]))
		}
		words = expandSchedule(words, 16)
		working := shaRounds(state, words, 0)
		for i := range state {
			state[i] = uint32((uint64(state[i]) + uint64(working[i])) & uint64(u32Mask))
		}
	}
	out := make([]byte, 32)
	for i, word := range state {
		binary.BigEndian.PutUint32(out[i*4:i*4+4], word)
	}
	return out, nil
}

func wordsLE4Even(data []byte) []uint32 {
	padded := append([]byte(nil), data...)
	if r := len(padded) % 4; r != 0 {
		padded = append(padded, make([]byte, 4-r)...)
	}
	if len(padded) == 0 {
		return nil
	}
	words := make([]uint32, 0, len(padded)/4+1)
	for i := 0; i < len(padded); i += 4 {
		words = append(words, binary.LittleEndian.Uint32(padded[i:i+4]))
	}
	if len(words)%2 != 0 {
		words = append(words, 0)
	}
	return words
}

func cs64Digest(data, digest []byte) (uint32, uint32) {
	mask := uint64(u32Mask)
	keyA := binary.LittleEndian.Uint32(digest[0:4]) | 1
	keyB := binary.LittleEndian.Uint32(digest[4:8]) | 1
	factors := [2]uint32{keyA * cs64Factor, keyB * cs64Factor}

	terms := make([]uint32, 0, len(cs64Coefficients)+8)
	offsets := make([]uint32, 0, len(cs64Coefficients)+8)
	for i, c := range cs64Coefficients {
		terms = append(terms, c[0]*factors[i%2])
		offsets = append(offsets, c[1])
	}
	prefixed := append([]byte{0}, data...)
	for i, word := range wordsLE4Even(prefixed) {
		term := uint64(word) * uint64(keyA)
		offset := uint64(rotate16(word)) * 0xEF0569FB
		if i%2 != 0 {
			term = uint64(word) * uint64(keyB)
			offset = uint64(rotate16(word)) * 0xC31713DB
		}
		if i == 0 {
			term += uint64(cs64Adjustment0) * uint64(factors[0])
			offset += uint64(cs64Adjustment1)
		}
		terms = append(terms, uint32(term&mask))
		offsets = append(offsets, uint32(offset&mask))
	}

	var swapAcc, swapLast, state, acc uint32
	for i := 0; i+1 < len(terms); i += 2 {
		x, y := uint64(terms[i]), uint64(terms[i+1])

		t := rotate16(uint32((uint64(offsets[i]) + x) & mask))
		q := (uint64(t) * 0x76F50F34) & mask
		swapAcc = uint32((uint64(swapAcc) + (uint64(rotate16(uint32(q)))*0xC3EFEA97 + q)) & mask)
		t = rotate16(uint32((uint64(offsets[i+1]) + y) & mask))
		q = (uint64(t) * 0x1881CE3C) & mask
		swapLast = uint32((uint64(rotate16(uint32(q)))*0x35BD1EC9 + q) & mask)
		swapAcc = uint32((uint64(swapAcc) + uint64(swapLast)) & mask)

		state = uint32((uint64(state)*uint64(keyA) + x) & mask)
		state = uint32((uint64(rotate16(state)) * 0xCF98B111) & mask)
		state = uint32((uint64(rotate16(state)) * 0x87085B9F) & mask)
		state = uint32((uint64(rotate16(state)) * 0x12CEB96D) & mask)
		state = uint32((uint64(rotate16(state)) * 0x257E1D83) & mask)
		acc = uint32((uint64(acc) + uint64(state)) & mask)

		t2 := uint32((uint64(state)*uint64(keyB) + y) & mask)
		t2 = uint32((uint64(rotate16(t2)) * 0xA27416F5) & mask)
		t2 = uint32((uint64(rotate16(t2)) * 0xD38396FF) & mask)
		state = uint32((uint64(rotate16(uint32((uint64(rotate16(t2))*0x7C932B89)&mask))) * 0xBFA49F69) & mask)
		acc = uint32((uint64(acc) + uint64(state)) & mask)
	}
	return swapLast ^ state, swapAcc ^ acc
}

// GenerateSecMSGEC returns the v2 token for a Unix timestamp (in seconds).
func GenerateSecMSGEC(unixTime int64) (string, error) {
	ticks := float64(unixTime) + windowsFileTimeEpoch
	ticks -= math.Mod(ticks, 300)
	ticks *= 1e9 / 100
	if math.IsNaN(ticks) || math.IsInf(ticks, 0) {
		return "", fmt.Errorf("invalid tick value from unix time %d", unixTime)
	}
	data := []byte(strings.TrimSuffix(fmt.Sprintf("%.0f", ticks), ".0") + trustedClientToken)
	digest, err := modifiedSHA256(data)
	if err != nil {
		return "", err
	}
	lo, hi := cs64Digest(data, digest)
	var cs64 [8]byte
	binary.LittleEndian.PutUint32(cs64[0:4], lo)
	binary.LittleEndian.PutUint32(cs64[4:8], hi)
	return strings.ToUpper(hex.EncodeToString(cs64[:])) + "-" + strings.ToUpper(hex.EncodeToString(digest)), nil
}
