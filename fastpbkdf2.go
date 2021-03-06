// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package fastpbkdf2 implements the key derivation function PBKDF2 as defined in
RFC 2898 / PKCS #5 v2.0.

A key derivation function is useful when encrypting data based on a password
or any other not-fully-random data. It uses a pseudorandom function to derive
a secure encryption key based on the password.

PBKDF2-HMAC-SHA1 is the only supported hash function, for now.
PBKDF2-HMAC-SHA2 will be supported in the future.
*/
package fastpbkdf2

import (
	"crypto/hmac"
	"crypto/sha1"
)

const (
	chunk = sha1.BlockSize
)

// Key derives a key from the password, salt and iteration count, returning a
// []byte of length keylen that can be used as cryptographic key. The key is
// derived based on the method described as PBKDF2 with the HMAC variant using
// the supplied hash function.
//
// For example, you can get a derived key for e.g. AES-256 (which needs a
// 32-byte key) by doing:
//
// 	dk := fastpbkdf2.SHA1([]byte("some password"), salt, 4096, 32)
//
// Remember to get a good random salt. At least 8 bytes is recommended by the
// RFC.
//
// Using a higher iteration count will increase the cost of an exhaustive
// search but will also make derivation proportionally slower.
func SHA1(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha1.New, password)
	numBlocks := (keyLen + sha1.Size - 1) / sha1.Size

	var inner, outer block
	hmac_init(&inner, &outer, password)

	var buf [4]byte
	var tmp block
	var U block
	dk := make([]byte, 0, numBlocks*sha1.Size)
	tpad := make([]byte, sha1.BlockSize)
	for block := 1; block <= numBlocks; block++ {
		// N.B.: || means concatenation, ^ means XOR
		// for each block T_i = U_1 ^ U_2 ^ ... ^ U_iter
		// U_1 = PRF(password, salt || uint(i))
		prf.Reset()
		prf.Write(salt)
		putUint32(buf[:], uint32(block))
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-sha1.Size:]

		//sha1_input(&tmp, T)
		for i := range tmp.h[:5] {
			tmp.h[i] = readUint32(T[i*4:])
		}
		// U_n = PRF(password, U_(n-1))
		copy(tpad, T)
		sha1_pad(tpad, sha1.BlockSize+sha1.Size)
		sha1_input(&U, tpad)
		for n := 2; n <= iter; n++ {
			sha1_block(&U, &inner, &U)
			sha1_block(&U, &outer, &U)
			tmp.h[0] ^= U.h[0]
			tmp.h[1] ^= U.h[1]
			tmp.h[2] ^= U.h[2]
			tmp.h[3] ^= U.h[3]
			tmp.h[4] ^= U.h[4]
		}
		sha1_output(T, &tmp)
	}
	return dk[:keyLen]
}

type block struct {
	h [16]uint32
}

const (
	init0 = 0x67452301
	init1 = 0xEFCDAB89
	init2 = 0x98BADCFE
	init3 = 0x10325476
	init4 = 0xC3D2E1F0
)

func sha1_init(b *block) {
	b.h[0] = init0
	b.h[1] = init1
	b.h[2] = init2
	b.h[3] = init3
	b.h[4] = init4
}

func sha1_pad(b []byte, len uint) {
	nx := len % chunk
	len *= 8 // message length in bits
	b[nx] = 0x80
	for i := nx + 1; i < chunk-8; i++ {
		b[i] = 0
	}
	putUint32(b[56:], uint32(len>>32))
	putUint32(b[60:], uint32(len))
}

/*
func sha1_block(dst, h, src *block) {
	// reads 160 bits from h,
	// 512 bits from src,
	// and writes 160 bits to dst
}*/

func sha1_input(bl *block, b []byte) {
	for i := range &bl.h {
		bl.h[i] = readUint32(b[i*4:])
	}
}

func sha1_output(b []byte, bl *block) {
	for i, x := range bl.h[:5] {
		putUint32(b[i*4:], x)
	}
}

// FIPS 198-1:
// https://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf

// key is zero padded to the block size of the hash function
// ipad = 0x36 byte repeated for key length
// opad = 0x5c byte repeated for key length
// hmac = H([key ^ opad] H([key ^ ipad] text))

func hmac_init(inner, outer *block, key []byte) {
	if len(key) > sha1.BlockSize {
		// If key is too big, hash it.
		sum := sha1.Sum(key)
		key = sum[:]
	}

	ipad := make([]byte, sha1.BlockSize)
	opad := make([]byte, sha1.BlockSize)
	copy(ipad, key)
	copy(opad, key)
	for i := range ipad {
		ipad[i] ^= 0x36
	}
	for i := range opad {
		opad[i] ^= 0x5c
	}

	var init block
	sha1_init(&init)
	sha1_input(inner, ipad)
	sha1_input(outer, opad)
	sha1_block(inner, &init, inner)
	sha1_block(outer, &init, outer)
}

func readUint32(x []byte) uint32 {
	_ = x[3]
	return uint32(x[0])<<24 | uint32(x[1])<<16 | uint32(x[2])<<8 | uint32(x[3])
}

func putUint32(x []byte, s uint32) {
	_ = x[3]
	x[0] = byte(s >> 24)
	x[1] = byte(s >> 16)
	x[2] = byte(s >> 8)
	x[3] = byte(s)
}
