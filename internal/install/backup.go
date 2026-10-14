package install

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/itsHesamHoseini/TunnelManager/internal/config"
	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
	"golang.org/x/crypto/scrypt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const backupLimit = 128 * 1024 * 1024

type backupManifest struct {
	Version int               `json:"version"`
	Hashes  map[string]string `json:"hashes"`
}

func EncryptArchive(files map[string][]byte, password string) ([]byte, error) {
	if len(password) < 16 {
		return nil, errors.New("backup passphrase must be at least 16 characters")
	}
	manifest := backupManifest{Version: 1, Hashes: map[string]string{}}
	for n, b := range files {
		sum := sha256.Sum256(b)
		manifest.Hashes[n] = fmt.Sprintf("%x", sum)
	}
	m, _ := json.Marshal(manifest)
	all := map[string][]byte{}
	for k, v := range files {
		all[k] = v
	}
	all["manifest.json"] = m
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for n, data := range all {
		if strings.Contains(n, "..") || filepath.IsAbs(n) {
			return nil, errors.New("invalid archive entry")
		}
		if e := tw.WriteHeader(&tar.Header{Name: n, Mode: 0600, Size: int64(len(data))}); e != nil {
			return nil, e
		}
		if _, e := tw.Write(data); e != nil {
			return nil, e
		}
	}
	tw.Close()
	gz.Close()
	if b.Len() > backupLimit {
		return nil, errors.New("backup exceeds 128 MiB limit")
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	key, e := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if e != nil {
		return nil, e
	}
	encrypted, e := secure.Seal(key, "tunnelmanager-backup-v1", b.Bytes())
	if e != nil {
		return nil, e
	}
	return append(append([]byte("TMB1"), salt...), encrypted...), nil
}
func DecryptArchive(data []byte, password string) (map[string][]byte, error) {
	if len(data) < 48 || len(data) > backupLimit || string(data[:4]) != "TMB1" {
		return nil, errors.New("invalid backup")
	}
	key, e := scrypt.Key([]byte(password), data[4:20], 32768, 8, 1, 32)
	if e != nil {
		return nil, e
	}
	plain, e := secure.Open(key, "tunnelmanager-backup-v1", data[20:])
	if e != nil {
		return nil, errors.New("wrong passphrase or damaged backup; nothing restored")
	}
	gz, e := gzip.NewReader(bytes.NewReader(plain))
	if e != nil {
		return nil, errors.New("invalid archive")
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, backupLimit))
	files := map[string][]byte{}
	total := int64(0)
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		if h.Typeflag != tar.TypeReg || h.Size < 0 || h.Size > backupLimit || strings.Contains(h.Name, "..") || filepath.IsAbs(h.Name) || files[h.Name] != nil {
			return nil, errors.New("unsafe archive entry")
		}
		if h.Name != "database.dump" && h.Name != "master.key" && h.Name != "db-password" && h.Name != "controller.json" && h.Name != "installation.json" && h.Name != "manifest.json" && h.Name != "tls/cert.pem" && h.Name != "tls/key.pem" {
			return nil, errors.New("unknown archive entry")
		}
		total += h.Size
		if total > backupLimit {
			return nil, errors.New("expanded archive too large")
		}
		b, e := io.ReadAll(tr)
		if e != nil {
			return nil, e
		}
		files[h.Name] = b
	}
	var m backupManifest
	if json.Unmarshal(files["manifest.json"], &m) != nil || m.Version != 1 {
		return nil, errors.New("manifest invalid")
	}
	for n, want := range m.Hashes {
		got := sha256.Sum256(files[n])
		if fmt.Sprintf("%x", got) != want {
			return nil, errors.New("backup integrity mismatch")
		}
	}
	if len(files["master.key"]) != 32 || len(files["database.dump"]) == 0 {
		return nil, errors.New("backup missing required data")
	}
	return files, nil
}
func (i *Installer) Backup(ctx context.Context, c config.Config, out, password string) error {
	dump, e := i.Compose(ctx, c, []string{"exec", "-T", "db", "pg_dump", "-U", "tunnelmanager", "-Fc", "tunnelmanager"}, nil)
	if e != nil {
		return errors.New("native database dump failed")
	}
	files := map[string][]byte{"database.dump": dump}
	for _, n := range []string{"master.key", "db-password", "controller.json", "tls/cert.pem", "tls/key.pem"} {
		b, e := os.ReadFile(filepath.Join(c.ConfigDir, n))
		if e != nil {
			return errors.New("protected runtime file missing")
		}
		files[n] = b
	}
	b, e := os.ReadFile(filepath.Join(c.Dir, "installation.json"))
	if e != nil {
		return e
	}
	files["installation.json"] = b
	encrypted, e := EncryptArchive(files, password)
	if e != nil {
		return e
	}
	return config.Atomic(out, encrypted, 0600)
}
func (i *Installer) Restore(ctx context.Context, c config.Config, path, password string, replace bool) (err error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return errors.New("backup unavailable")
	}
	files, e := DecryptArchive(b, password)
	if e != nil {
		return e
	}
	if !replace {
		return errors.New("restore requires explicit --replace confirmation after preview")
	}
	snapshot, e := Snapshot(c)
	if e != nil {
		return e
	}
	oldDump, e := i.Compose(ctx, c, []string{"exec", "-T", "db", "pg_dump", "-U", "tunnelmanager", "-Fc", "tunnelmanager"}, nil)
	if e != nil {
		return errors.New("pre-restore dump failed")
	}
	if e = config.Atomic(filepath.Join(snapshot, "database.dump"), oldDump, 0600); e != nil {
		return e
	}
	if _, e = i.Compose(ctx, c, []string{"stop", "controller", "edge"}, nil); e != nil {
		return e
	}
	success := false
	defer func() {
		if success {
			return
		}
		if e := RestoreSnapshot(c, snapshot); e != nil {
			err = errors.New("restore rollback files failed; controller remains stopped; snapshot preserved")
			return
		}
		repair, done := context.WithTimeout(context.Background(), 3*time.Minute)
		defer done()
		if _, e := i.Compose(repair, c, []string{"exec", "-T", "db", "pg_restore", "-U", "tunnelmanager", "-d", "tunnelmanager", "--clean", "--if-exists", "--single-transaction", "--no-owner", "--no-acl"}, bytes.NewReader(oldDump)); e != nil {
			err = errors.New("restore rollback database failed; controller remains stopped; snapshot preserved")
			return
		}
		if _, e := i.Compose(repair, c, []string{"up", "-d", "--force-recreate", "--wait"}, nil); e != nil {
			err = errors.New("restore rollback health failed; snapshot preserved")
		}
	}()
	for _, n := range []string{"master.key", "tls/cert.pem", "tls/key.pem"} {
		if e = config.Atomic(filepath.Join(c.ConfigDir, n), files[n], 0600); e != nil {
			return e
		}
	}
	if _, e = i.Compose(ctx, c, []string{"exec", "-T", "db", "pg_restore", "-U", "tunnelmanager", "-d", "tunnelmanager", "--clean", "--if-exists", "--single-transaction", "--no-owner", "--no-acl"}, bytes.NewReader(files["database.dump"])); e != nil {
		return errors.New("restore failed; previous snapshot recovery started")
	}
	i.Compose(ctx, c, []string{"exec", "-T", "db", "psql", "-U", "tunnelmanager", "-d", "tunnelmanager", "-c", "DELETE FROM sessions; DELETE FROM challenges; DELETE FROM enrollment;"}, nil)
	if _, e = i.Compose(ctx, c, []string{"up", "-d", "--force-recreate", "--wait"}, nil); e != nil {
		return errors.New("restored controller failed health; previous snapshot recovery started")
	}
	success = true
	return nil
}
