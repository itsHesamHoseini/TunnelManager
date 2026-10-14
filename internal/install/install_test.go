package install

import (
	"context"
	"github.com/itsHesamHoseini/TunnelManager/internal/config"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptedBackupAndTamper(t *testing.T) {
	files := map[string][]byte{"database.dump": []byte("synthetic-database"), "master.key": make([]byte, 32)}
	b, e := EncryptArchive(files, "Synthetic-Backup-Password!")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecryptArchive(b, "wrong"); e == nil {
		t.Fatal("wrong password accepted")
	}
	got, e := DecryptArchive(b, "Synthetic-Backup-Password!")
	if e != nil || string(got["database.dump"]) != "synthetic-database" {
		t.Fatal("roundtrip failed")
	}
	b[len(b)-1] ^= 1
	if _, e = DecryptArchive(b, "Synthetic-Backup-Password!"); e == nil {
		t.Fatal("tampered backup accepted")
	}
}
func TestSnapshotAndBoundaries(t *testing.T) {
	c := config.Default()
	c.Dir = t.TempDir()
	c.ConfigDir = filepath.Join(c.Dir, "config")
	os.MkdirAll(c.ConfigDir, 0700)
	config.Atomic(filepath.Join(c.ConfigDir, "master.key"), []byte("original"), 0600)
	config.Atomic(filepath.Join(c.Dir, "nginx.conf"), []byte("old"), 0600)
	path, e := Snapshot(c)
	if e != nil {
		t.Fatal(e)
	}
	config.Atomic(filepath.Join(c.Dir, "nginx.conf"), []byte("new"), 0600)
	if e = RestoreSnapshot(c, path); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(filepath.Join(c.Dir, "nginx.conf"))
	if string(b) != "old" {
		t.Fatal("rollback failed")
	}
	c.Domain = "panel.example.com"
	c.Dir = "/"
	if Validate(c) == nil {
		t.Fatal("root directory accepted")
	}
}
func TestTLSNameAndKeys(t *testing.T) {
	c := config.Default()
	c.ConfigDir = t.TempDir()
	c.Domain = "panel.example.com"
	i := New()
	if e := i.TLS(context.Background(), c); e != nil {
		t.Fatal(e)
	}
	cert, _ := os.ReadFile(filepath.Join(c.ConfigDir, "tls/cert.pem"))
	key, _ := os.ReadFile(filepath.Join(c.ConfigDir, "tls/key.pem"))
	if VerifyCertificate(cert, key, "other.example.net") == nil {
		t.Fatal("wrong hostname accepted")
	}
	if VerifyCertificate(cert, key, c.Domain) != nil {
		t.Fatal("valid certificate rejected")
	}
}

func TestOwnedDatabasePurge(t *testing.T) {
	c := config.Default()
	c.Domain = "panel.example.com"
	c.Dir = t.TempDir()
	c.ConfigDir = filepath.Join(c.Dir, "config")
	c.DataDir = filepath.Join(c.Dir, "data")
	target := filepath.Join(c.DataDir, "postgres")
	if PurgeData(c) == nil {
		t.Fatal("unowned data purge accepted")
	}
	if e := PrepareData(c, false); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(target, "synthetic.db"), []byte("fixture"), 0600)
	keep := filepath.Join(c.DataDir, "keep.backup")
	os.WriteFile(keep, []byte("fixture"), 0600)
	other := c
	other.ConfigDir = filepath.Join(c.Dir, "other")
	if PurgeData(other) == nil {
		t.Fatal("other installation purged data")
	}
	if e := PurgeData(c); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(target); !os.IsNotExist(e) {
		t.Fatal("owned postgres subtree retained")
	}
	if _, e := os.Stat(keep); e != nil {
		t.Fatal("unrelated backup removed")
	}
	os.MkdirAll(target, 0700)
	os.WriteFile(filepath.Join(target, "unowned.db"), []byte("fixture"), 0600)
	if PrepareData(c, false) == nil {
		t.Fatal("populated unowned data adopted")
	}
}

func TestDataSymlinkRefused(t *testing.T) {
	c := config.Default()
	c.Domain = "panel.example.com"
	c.Dir = t.TempDir()
	c.ConfigDir = filepath.Join(c.Dir, "config")
	c.DataDir = filepath.Join(c.Dir, "data")
	external := t.TempDir()
	if e := os.Symlink(external, c.DataDir); e != nil {
		t.Skip("symlink creation unavailable on this platform")
	}
	if PrepareData(c, false) == nil || PurgeData(c) == nil {
		t.Fatal("symlink data directory accepted")
	}
}
