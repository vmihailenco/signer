Message signing using HMAC for Golang
=====================================

There are 2 types of signers:
- Signer and TimeSigner that use binary encoding.
- Base64Signer and Base64TimeSigner that use base64 encoding and are compatible with Python's itsdangerous lib.

API docs: http://godoc.org/github.com/vmihailenco/signer

Example
-------

Sign:

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

Verify:

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
