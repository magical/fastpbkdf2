// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fastpbkdf2

//go:noescape
func blockAMD64(dig *block, p []byte)

func sha1_block(dst, init, src *block) {
	dig := *init
	var p [64]byte
	for i, x := range src.h[:] {
		putUint32(p[i*4:], x)
	}
	blockAMD64(&dig, p[:])
	copy(dst.h[:5], dig.h[:5])
}
