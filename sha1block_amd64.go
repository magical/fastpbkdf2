// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fastpbkdf2

//go:noescape
func blockAMD64(dst, init, src *block)

func sha1_block(dst, init, src *block) {
	blockAMD64(dst, init, src)
}
