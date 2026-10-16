package nodeops

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"io"
	"os"
)

func fileDigest(path string) (string, error) {
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Size() > 64*1024*1024 {
		return "", errors.New("binary_unavailable")
	}
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	_, e = io.Copy(h, io.LimitReader(f, 64*1024*1024+1))
	return fmt.Sprintf("%x", h.Sum(nil)), e
}
func verifiedBinary(path string, a engine.Artifact) bool {
	b, e := readRegular(path+".artifact.json", 65536)
	if e != nil {
		return false
	}
	var v struct {
		Artifact   engine.Artifact
		BinaryHash string
	}
	if json.Unmarshal(b, &v) != nil || v.Artifact.SHA256 != a.SHA256 {
		return false
	}
	hash, e := fileDigest(path)
	return e == nil && hash == v.BinaryHash
}
