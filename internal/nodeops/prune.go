package nodeops

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Expired commands cannot execute even after receipt retention. Active watchdog
// journals are never collected, and each maintenance pass has a finite I/O budget.
func (r *Runtime) prune(now time.Time) {
	if !r.lastPrune.IsZero() && now.Sub(r.lastPrune) < time.Hour {
		return
	}
	r.lastPrune = now
	stop := time.Now().Add(time.Second)
	for _, folder := range []string{"receipts", "events", "changes", "certificate-transactions", "log-transactions"} {
		entries, e := os.ReadDir(r.file(folder))
		if e != nil {
			continue
		}
		for _, entry := range entries {
			if time.Now().After(stop) {
				return
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			st, e := entry.Info()
			if e != nil || !st.Mode().IsRegular() {
				continue
			}
			age := now.Sub(st.ModTime())
			limit := 30 * 24 * time.Hour
			if folder == "receipts" {
				limit = 24 * time.Hour
			}
			if age < limit {
				continue
			}
			path := r.file(folder, entry.Name())
			if folder == "changes" || folder == "certificate-transactions" || folder == "log-transactions" {
				var state struct{ Phase string }
				b, e := os.ReadFile(path)
				if e != nil || json.Unmarshal(b, &state) != nil || (state.Phase != "confirmed" && state.Phase != "reverted" && state.Phase != "released") {
					continue
				}
				if folder == "changes" {
					os.Remove(r.file("backups", strings.TrimSuffix(filepath.Base(path), ".json")+".toml"))
				}
			}
			os.Remove(path)
		}
	}
}
