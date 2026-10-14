package install

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/itsHesamHoseini/TunnelManager/internal/config"
)

func dataOwner(c config.Config) []byte {
	sum := sha256.Sum256([]byte(filepath.Clean(c.Dir) + "\n" + filepath.Clean(c.ConfigDir)))
	return []byte(fmt.Sprintf("TunnelManager postgres v1\n%x\n", sum))
}

func dataPath(c config.Config) (string, error) {
	if e := Validate(c); e != nil {
		return "", e
	}
	parent := filepath.Clean(c.DataDir)
	// Check existing components before creating or removing anything.
	for p := parent; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil && !os.IsNotExist(e) {
			return "", e
		}
		if e == nil && (st.Mode()&os.ModeSymlink != 0 || !st.IsDir()) {
			return "", errors.New("data directory must have real directory parents; symlinks refused")
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	target := filepath.Join(parent, "postgres")
	if st, e := os.Lstat(target); e == nil && (st.Mode()&os.ModeSymlink != 0 || !st.IsDir()) {
		return "", errors.New("postgres data target is not a real directory")
	}
	return target, nil
}

func PrepareData(c config.Config, existing bool) error {
	target, e := dataPath(c)
	if e != nil {
		return e
	}
	marker := filepath.Join(c.DataDir, ".postgres-owner")
	if b, e := os.ReadFile(marker); e == nil {
		if string(b) != string(dataOwner(c)) {
			return errors.New("data belongs to another installation; preserved")
		}
	} else {
		entries, e := os.ReadDir(target)
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		if len(entries) > 0 {
			old, e := config.Load(filepath.Join(c.Dir, "installation.json"))
			if !existing || e != nil || filepath.Clean(old.DataDir) != filepath.Clean(c.DataDir) || old.ConfigDir != c.ConfigDir {
				return errors.New("populated unowned database directory; choose a dedicated empty data directory")
			}
		}
		if e = config.Atomic(marker, dataOwner(c), 0600); e != nil {
			return e
		}
	}
	return os.MkdirAll(target, 0700)
}

func PurgeData(c config.Config) error {
	target, e := dataPath(c)
	if e != nil {
		return e
	}
	marker := filepath.Join(c.DataDir, ".postgres-owner")
	b, e := os.ReadFile(marker)
	if e != nil || string(b) != string(dataOwner(c)) {
		return errors.New("database ownership unavailable; data preserved")
	}
	if e = os.RemoveAll(target); e != nil {
		return e
	}
	return os.Remove(marker)
}
