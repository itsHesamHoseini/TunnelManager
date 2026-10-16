//go:build linux

package nodeops

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"time"
)

func mutationLock(ctx context.Context, path string) (func(), error) {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	for {
		if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e == nil {
			return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
