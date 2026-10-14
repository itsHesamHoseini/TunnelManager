package install

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

func OSAndMemory() []string {
	out := []string{}
	b, e := os.ReadFile("/etc/os-release")
	if e == nil {
		known := false
		for _, v := range []string{"VERSION_ID=\"22.04\"", "VERSION_ID=\"24.04\"", "VERSION_ID=\"11\"", "VERSION_ID=\"12\""} {
			if strings.Contains(string(b), v) {
				known = true
			}
		}
		if !known {
			out = append(out, "WARN: OS version outside tested Ubuntu 22.04/24.04 and Debian 11/12 targets; continuing is explicit operator choice.")
		}
	}
	if runtime.GOOS != "linux" {
		return out
	}
	b, e = os.ReadFile("/proc/meminfo")
	if e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "MemAvailable:") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					n, _ := strconv.ParseUint(fields[1], 10, 64)
					if n < 512*1024 {
						out = append(out, "WARN: less than 512 MiB available RAM; release memory before controller installation.")
					}
				}
			}
		}
	}
	return out
}
func existingParent(path string) string {
	for {
		if _, e := os.Stat(path); e == nil {
			return path
		}
		next := filepath.Dir(path)
		if next == path {
			return "/"
		}
		path = next
	}
}
