//go:build linux

package install

import "golang.org/x/sys/unix"

func DiskCheck(path string) []string {
	var s unix.Statfs_t
	if unix.Statfs(existingParent(path), &s) != nil {
		return []string{"WARN: available disk could not be measured."}
	}
	if s.Bavail*uint64(s.Bsize) < 1024*1024*1024 {
		return []string{"FAIL: at least 1 GiB free disk is required for controller images and backup."}
	}
	return []string{}
}
