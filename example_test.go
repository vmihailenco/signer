package signer_test

import (
	"crypto/hmac"
	"crypto/md5"
	"fmt"
	"hash"

	"github.com/vmihailenco/signer"
)

func ExampleSign() {
	h := hmac.New(func() hash.Hash {
		return md5.New()
	}, []byte("secret"))
	s := signer.NewBase64Signer(h)

	msg := []byte("hello")
	b := s.Sign(msg)

	fmt.Println(string(b))
	// Output: hello.ut5jhjxh7QsxZYBuzWrO_A
}

func ExampleVerify() {
	h := hmac.New(func() hash.Hash {
		return md5.New()
	}, []byte("secret"))
	s := signer.NewBase64Signer(h)

	b := []byte("hello.ut5jhjxh7QsxZYBuzWrO_A")
	msg, ok := s.Verify(b)

	fmt.Println(ok)
	fmt.Println(string(msg))
	// Output:
	// true
	// hello
}
