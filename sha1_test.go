package fastpbkdf2

import (
	"bytes"
	"crypto/sha1"
	"testing"
)

func sha1_sum(msg []byte) []byte {
	if len(msg) > 55 {
		panic("msg too long")
	}
	var ctx block
	var in block
	pad := make([]byte, sha1.BlockSize)
	out := make([]byte, sha1.Size)
	sha1_init(&ctx)
	copy(pad, msg)
	sha1_pad(pad, uint(len(msg)))
	sha1_input(&in, pad)
	sha1_block(&ctx, &ctx, &in)
	sha1_output(out, &ctx)
	return out
}

func Test_sha1(t *testing.T) {
	msg := []byte("password")
	got := sha1_sum(msg)
	want := sha1.Sum(msg)
	if !bytes.Equal(got, want[:]) {
		t.Errorf("got %x, want %x", got, want[:])
	}
}
