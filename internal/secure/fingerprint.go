package secure

import (
	"crypto/sha256"
	"encoding/base64"
)

func Fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}
