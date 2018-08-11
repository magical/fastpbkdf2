// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fastpbkdf2

const (
	_K0 = 0x5A827999
	_K1 = 0x6ED9EBA1
	_K2 = 0x8F1BBCDC
	_K3 = 0xCA62C1D6
)

// sha1_block_generic is a portable, pure Go version of the SHA-1 block step.
// It's used by sha1block_generic.go and tests.
func sha1_block_generic(dst, init, src *block) {
	w := src.h
	h0, h1, h2, h3, h4 := init.h[0], init.h[1], init.h[2], init.h[3], init.h[4]
	a, b, c, d, e := h0, h1, h2, h3, h4

	// Each of the four 20-iteration rounds
	// differs only in the computation of f and
	// the choice of K (_K0, _K1, etc).
	i := 0
	for ; i < 16; i++ {
		f := b&c | (^b)&d
		a5 := a<<5 | a>>(32-5)
		b30 := b<<30 | b>>(32-30)
		t := a5 + f + e + w[i&0xf] + _K0
		a, b, c, d, e = t, a, b30, c, d
	}
	for ; i < 20; i++ {
		tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
		w[i&0xf] = tmp<<1 | tmp>>(32-1)

		f := b&c | (^b)&d
		a5 := a<<5 | a>>(32-5)
		b30 := b<<30 | b>>(32-30)
		t := a5 + f + e + w[i&0xf] + _K0
		a, b, c, d, e = t, a, b30, c, d
	}
	for ; i < 40; i++ {
		tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
		w[i&0xf] = tmp<<1 | tmp>>(32-1)
		f := b ^ c ^ d
		a5 := a<<5 | a>>(32-5)
		b30 := b<<30 | b>>(32-30)
		t := a5 + f + e + w[i&0xf] + _K1
		a, b, c, d, e = t, a, b30, c, d
	}
	for ; i < 60; i++ {
		tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
		w[i&0xf] = tmp<<1 | tmp>>(32-1)
		f := ((b | c) & d) | (b & c)

		a5 := a<<5 | a>>(32-5)
		b30 := b<<30 | b>>(32-30)
		t := a5 + f + e + w[i&0xf] + _K2
		a, b, c, d, e = t, a, b30, c, d
	}
	for ; i < 80; i++ {
		tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
		w[i&0xf] = tmp<<1 | tmp>>(32-1)
		f := b ^ c ^ d
		a5 := a<<5 | a>>(32-5)
		b30 := b<<30 | b>>(32-30)
		t := a5 + f + e + w[i&0xf] + _K3
		a, b, c, d, e = t, a, b30, c, d
	}

	h0 += a
	h1 += b
	h2 += c
	h3 += d
	h4 += e

	dst.h[0], dst.h[1], dst.h[2], dst.h[3], dst.h[4] = h0, h1, h2, h3, h4
}
