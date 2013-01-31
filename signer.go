package signer

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"time"
)

const (
	itsDangerousEpoch = 1293840000
)

type Signer struct {
	h hash.Hash
}

func NewSigner(h hash.Hash) *Signer {
	return &Signer{
		h: h,
	}
}

func (s *Signer) signature(msg []byte) []byte {
	s.h.Reset()
	s.h.Write(msg)
	return s.h.Sum(nil)
}

func (s *Signer) Sign(msg []byte) []byte {
	b := make([]byte, 8+len(msg))
	binary.PutVarint(b, int64(len(msg)))
	b = append(b[:8], msg...)
	b = append(b, s.signature(b)...)
	return b
}

func (s *Signer) Verify(b []byte) ([]byte, bool) {
	if len(b) < 8 {
		return nil, false
	}

	length, _ := binary.Varint(b[:8])
	if length < 0 {
		return nil, false
	}

	length += 8
	if length > int64(len(b)) {
		return nil, false
	}

	msg := b[8:length]
	signature := b[length:]
	signature2 := s.signature(b[:length])
	return msg, subtle.ConstantTimeCompare(signature, signature2) == 1
}

type TimeSigner struct {
	*Signer
}

func NewTimeSigner(h hash.Hash) *TimeSigner {
	return &TimeSigner{
		Signer: NewSigner(h),
	}
}

func (s *TimeSigner) Sign(msg []byte) []byte {
	b := make([]byte, 8+len(msg))
	binary.PutVarint(b, time.Now().Unix())
	b = append(b[:8], msg...)
	return s.Signer.Sign(b)
}

func (s *TimeSigner) Verify(b []byte, dur time.Duration) ([]byte, bool) {
	msg, ok := s.Signer.Verify(b)
	if !ok {
		return nil, ok
	}

	unixTime, _ := binary.Varint(msg[:8])
	if time.Since(time.Unix(unixTime, 0)) > dur {
		return nil, false
	}
	return msg[8:], true
}

type Base64Signer struct {
	h   hash.Hash
	Sep []byte
}

func NewBase64Signer(h hash.Hash) *Base64Signer {
	return &Base64Signer{
		h:   h,
		Sep: []byte{'.'},
	}
}

func (s *Base64Signer) base64Encode(b []byte) []byte {
	dst := make([]byte, base64.URLEncoding.EncodedLen(len(b)))
	base64.URLEncoding.Encode(dst, b)
	for i := len(dst) - 1; i > 0; i-- {
		if dst[i] == '=' {
			dst = dst[:i]
		}
	}
	return dst
}

func (s *Base64Signer) base64Decode(b []byte) ([]byte, error) {
	for i := 0; i < len(b)%4; i++ {
		b = append(b, '=')
	}

	dst := make([]byte, base64.URLEncoding.DecodedLen(len(b)))
	n, err := base64.URLEncoding.Decode(dst, b)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

func (s *Base64Signer) signature(b []byte) []byte {
	s.h.Reset()
	s.h.Write(b)
	return s.base64Encode(s.h.Sum(nil))
}

func (s *Base64Signer) Sign(msg []byte) []byte {
	signature := s.signature(msg)
	msg = append(msg, s.Sep...)
	msg = append(msg, signature...)
	return msg
}

func (s Base64Signer) Verify(b []byte) ([]byte, bool) {
	parts := splitRight(b, s.Sep)
	if len(parts) != 2 {
		return nil, false
	}
	msg, signature := parts[0], parts[1]
	signature2 := s.signature(msg)
	if subtle.ConstantTimeCompare(signature, signature2) != 1 {
		return nil, false
	}
	return msg, true
}

type Base64TimeSigner struct {
	*Base64Signer
}

func NewBase64TimeSigner(h hash.Hash) *Base64TimeSigner {
	return &Base64TimeSigner{
		Base64Signer: NewBase64Signer(h),
	}
}

func (s *Base64TimeSigner) encodeTime(unixTime int64) []byte {
	unixTime -= itsDangerousEpoch
	b := make([]byte, 0, 8)
	for i := uint(0); unixTime > 0; i++ {
		unixTime >>= i * 8
		b = append(b, byte(unixTime))
	}
	return s.base64Encode(b)
}

func (s *Base64TimeSigner) decodeTime(b []byte) int64 {
	b, err := s.base64Decode(b)
	if err != nil {
		return 0
	}

	var unixTime int64
	for i, v := range b {
		pos := len(b) - 1 - i
		unixTime |= int64(v) << (uint(pos) * 8)
	}
	unixTime += itsDangerousEpoch
	return unixTime
}

func (s *Base64TimeSigner) Sign(msg []byte) []byte {
	now := time.Now().Unix()
	msg = append(msg, s.Sep...)
	msg = append(msg, s.encodeTime(now)...)
	return s.Base64Signer.Sign(msg)
}

func (s *Base64TimeSigner) Verify(b []byte, dur time.Duration) ([]byte, bool) {
	msg, ok := s.Base64Signer.Verify(b)
	if !ok {
		return nil, false
	}

	parts := splitRight(msg, s.Sep)
	if len(parts) != 2 {
		return nil, false
	}
	msg, timeBytes := parts[0], parts[1]
	unixTime := s.decodeTime(timeBytes)
	if time.Since(time.Unix(unixTime, 0)) > dur {
		return nil, false
	}

	return msg, true
}

func splitRight(b []byte, sep []byte) [][]byte {
	ind := bytes.LastIndex(b, sep)
	if ind <= -1 {
		return [][]byte{b}
	}
	return [][]byte{b[:ind], b[ind+1:]}
}
