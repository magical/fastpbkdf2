package fastpbkdf2

import (
	"bytes"
	"crypto/sha1"
	"testing"
)

func Test_sha1(t *testing.T) {
	msg := []byte("password")

	var ctx block
	var in block
	pad := make([]byte, sha1.BlockSize)
	got := make([]byte, sha1.Size)

	sha1_init(&ctx)
	copy(pad, msg)
	sha1_pad(pad, uint(len(msg)))
	sha1_input(&in, pad)
	//fmt.Printf("%x", pad)
	sha1_block(&ctx, &ctx, &in)
	sha1_output(got, &ctx)

	want := sha1.Sum(msg)
	if !bytes.Equal(got, want[:]) {
		t.Errorf("got %x, want %x", got, want[:])
	}
}
