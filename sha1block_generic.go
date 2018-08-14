// +build !amd64

package fastpbkdf2

func sha1_block(dst, init, src *block) {
	sha1_block_generic(dst, init, src)
}
