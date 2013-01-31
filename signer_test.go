package signer_test

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"hash"
	"testing"
	"time"

	"github.com/vmihailenco/signer"

	. "launchpad.net/gocheck"
)

var (
	h = hmac.New(func() hash.Hash {
		return md5.New()
	}, []byte("foo-bar"))
)

func Test(t *testing.T) { TestingT(t) }

type SignerTest struct{}

var _ = Suite(&SignerTest{})

func (t *SignerTest) TestSigner(c *C) {
	s := signer.NewSigner(h)

	table := []struct {
		data    []byte
		message []byte
	}{
		{
			data:    []byte{0x68, 0x65, 0x6c, 0x6c, 0x6f},
			message: []byte{0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0xd3, 0xa4, 0x8a, 0x32, 0x96, 0xa6, 0x30, 0x27, 0x3e, 0x1b, 0x38, 0xf6, 0x78, 0x7b, 0x97, 0xa9, 0x53, 0x8c, 0xc5, 0xf9},
		},
		{
			data:    nil,
			message: []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9b, 0x66, 0x7, 0x54, 0x9d, 0x15, 0xcc, 0x3b, 0x82, 0xda, 0x27, 0x8e, 0x6c, 0xf1, 0x8e, 0xcf, 0xc2, 0x9e, 0x9d, 0x8d},
		},
	}
	for _, r := range table {
		for i := 0; i < 10; i++ {
			c.Assert(s.Sign(r.data), DeepEquals, r.message)
			data, ok := s.Verify(r.message)
			c.Assert(data, HasLen, len(r.data))
			if len(data) > 0 {
				c.Assert(data, DeepEquals, r.data)
			}
			c.Assert(ok, Equals, true)
		}
	}
}

func (t *SignerTest) TestVerify(c *C) {
	s := signer.NewSigner(h)

	table := [][]byte{
		nil,
		[]byte{0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		[]byte{0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		[]byte{0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
	}
	for _, msg := range table {
		for i := 0; i < 10; i++ {
			data, ok := s.Verify(msg)
			c.Assert(data, IsNil)
			c.Assert(ok, Equals, false)
		}
	}
}

func (t *SignerTest) TestTimeSigner(c *C) {
	s := signer.NewTimeSigner(h)

	data := []byte("hello")
	msg := s.Sign(data)
	data2, ok := s.Verify(msg, time.Minute)
	c.Assert(ok, Equals, true)
	c.Assert(data2, DeepEquals, data)
}

func (t *SignerTest) TestTimeSignerZeroDuration(c *C) {
	s := signer.NewTimeSigner(h)

	data := []byte("hello")
	msg := s.Sign(data)
	data2, ok := s.Verify(msg, 0)
	c.Assert(ok, Equals, false)
	c.Assert(data2, IsNil)
}

func (t *SignerTest) TestStringSigner(c *C) {
	s := signer.NewBase64Signer(h)

	table := []struct {
		msg []byte
		b   []byte
	}{
		{
			msg: []byte{0x68, 0x65, 0x6c, 0x6c, 0x6f},
			b:   []byte{0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x2e, 0x7a, 0x5f, 0x36, 0x74, 0x5f, 0x59, 0x58, 0x54, 0x2d, 0x4b, 0x5f, 0x4c, 0x6b, 0x69, 0x38, 0x77, 0x68, 0x4d, 0x65, 0x62, 0x39, 0x75, 0x43, 0x70, 0x42, 0x37, 0x6f},
		},
		{
			msg: []byte{},
			b:   []byte{0x2e, 0x6d, 0x72, 0x49, 0x56, 0x70, 0x56, 0x6b, 0x34, 0x55, 0x65, 0x41, 0x63, 0x70, 0x61, 0x49, 0x61, 0x51, 0x51, 0x34, 0x32, 0x38, 0x75, 0x36, 0x6a, 0x52, 0x57, 0x63},
		},
	}
	for _, r := range table {
		for i := 0; i < 10; i++ {
			c.Assert(s.Sign(r.msg), DeepEquals, r.b)
			msg, ok := s.Verify(r.b)
			c.Assert(msg, HasLen, len(r.msg))
			if len(msg) > 0 {
				c.Assert(msg, DeepEquals, r.msg)
			}
			c.Assert(ok, Equals, true)
		}
	}
}

func (t *SignerTest) TestItsDangerousSignerCompatibility(c *C) {
	sha1Hash := sha1.New()
	sha1Hash.Write([]byte("itsdangerous.Signersignerfoo-bar"))
	key := sha1Hash.Sum(nil)
	h = hmac.New(func() hash.Hash {
		return sha1.New()
	}, key)

	s := signer.NewBase64Signer(h)
	msg := s.Sign([]byte("hello"))
	c.Assert(string(msg), Equals, "hello.z_6t_YXT-K_Lki8whMeb9uCpB7o")
}

func (t *SignerTest) TestItsDangerousTimeSignerCompatibility(c *C) {
	c.Skip("expired")

	sha1Hash := sha1.New()
	sha1Hash.Write([]byte("itsdangerous.Signersignerfoo-bar"))
	key := sha1Hash.Sum(nil)
	h = hmac.New(func() hash.Hash {
		return sha1.New()
	}, key)

	s := signer.NewBase64TimeSigner(h)
	msg, ok := s.Verify([]byte("hello.A-wDUg.SvVp6Cqp_MHLn776aSQzNyN6flc"), time.Hour)
	c.Assert(ok, Equals, true)
	c.Assert(msg, DeepEquals, []byte("hello"))
}

func (t *SignerTest) BenchmarkSign(c *C) {
	s := signer.NewSigner(h)
	data := []byte("hello")

	for i := 0; i < c.N; i++ {
		s.Sign(data)
	}
}

func (t *SignerTest) BenchmarkVerify(c *C) {
	s := signer.NewSigner(h)
	msg := []byte{0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x85, 0xc5, 0xc2, 0xd, 0x33, 0xc0, 0x28, 0xd7, 0xda, 0x70, 0xdc, 0x85, 0x37, 0x3f, 0xe7, 0x40}

	for i := 0; i < c.N; i++ {
		s.Verify(msg)
	}
}

func (t *SignerTest) BenchmarkTimeSign(c *C) {
	s := signer.NewTimeSigner(h)
	data := []byte("hello")

	for i := 0; i < c.N; i++ {
		s.Sign(data)
	}
}

func (t *SignerTest) BenchmarkTimeVerify(c *C) {
	s := signer.NewTimeSigner(h)
	msg := []byte{0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x85, 0xc5, 0xc2, 0xd, 0x33, 0xc0, 0x28, 0xd7, 0xda, 0x70, 0xdc, 0x85, 0x37, 0x3f, 0xe7, 0x40}

	for i := 0; i < c.N; i++ {
		s.Verify(msg, time.Minute)
	}
}

func (t *SignerTest) BenchmarkBase64Sign(c *C) {
	s := signer.NewBase64Signer(h)
	data := []byte("hello")

	for i := 0; i < c.N; i++ {
		s.Sign(data)
	}
}
