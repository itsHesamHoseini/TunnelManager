package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
	"time"
)

func Token(n int) string {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func Hash(s string) string { h := sha256.Sum256([]byte(s)); return fmt.Sprintf("%x", h) }
func Password(s string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	v := argon2.IDKey([]byte(s), salt, 2, 32*1024, 1, 32)
	return base64.RawStdEncoding.EncodeToString(salt) + "." + base64.RawStdEncoding.EncodeToString(v)
}
func VerifyPassword(p, h string) bool {
	x := strings.Split(h, ".")
	if len(x) != 2 {
		return false
	}
	salt, e := base64.RawStdEncoding.DecodeString(x[0])
	if e != nil || len(salt) != 16 {
		return false
	}
	want, e := base64.RawStdEncoding.DecodeString(x[1])
	if e != nil || len(want) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(p), salt, 2, 32*1024, 1, 32)
	return subtle.ConstantTimeCompare(want, got) == 1
}
func Seal(key []byte, scope string, data []byte) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	n := make([]byte, a.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return nil, e
	}
	return a.Seal(n, n, data, []byte(scope)), nil
}
func Open(key []byte, scope string, data []byte) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	if e != nil || len(data) < a.NonceSize() {
		return nil, fmt.Errorf("invalid encrypted record")
	}
	return a.Open(nil, data[:a.NonceSize()], data[a.NonceSize():], []byte(scope))
}
func NewTOTP() string {
	b := make([]byte, 20)
	rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}
func Code(secret string, step int64) string {
	k, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if e != nil {
		return ""
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(step))
	h := hmac.New(sha1.New, k)
	h.Write(b)
	s := h.Sum(nil)
	o := s[len(s)-1] & 15
	v := binary.BigEndian.Uint32(s[o:o+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000)
}
func TOTP(secret, code string, last int64, now time.Time) (int64, bool) {
	if len(code) != 6 {
		return last, false
	}
	for _, d := range []int64{0, -1, 1} {
		step := now.Unix()/30 + d
		if step > last && subtle.ConstantTimeCompare([]byte(Code(secret, step)), []byte(code)) == 1 {
			return step, true
		}
	}
	return last, false
}
