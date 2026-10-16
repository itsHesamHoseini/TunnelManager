package nodeops

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
)

// The rollback executable and identity must survive an unfinished transaction.
func (r *Runtime) PendingRollback() error {
	for _, folder := range []string{"changes", "certificate-transactions", "log-transactions"} {
		entries, e := os.ReadDir(r.file(folder))
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		for _, v := range entries {
			if v.IsDir() || !strings.HasSuffix(v.Name(), ".json") {
				continue
			}
			b, e := os.ReadFile(r.file(folder, v.Name()))
			var state struct{ Phase string }
			if e != nil || json.Unmarshal(b, &state) != nil {
				return errors.New("rollback_journal_unreadable")
			}
			if state.Phase != "confirmed" && state.Phase != "reverted" {
				return errors.New("finish_or_revert_pending_changes_before_uninstall")
			}
		}
	}
	return nil
}
