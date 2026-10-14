//go:build !linux

package install

func DiskCheck(path string) []string {
	return []string{"WARN: native Linux disk check untested on this OS."}
}
