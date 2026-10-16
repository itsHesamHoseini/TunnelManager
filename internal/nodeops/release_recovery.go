package nodeops

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"os"
)

// Release is deliberately different from rollback: preserve current bytes and
// process intent; disarm only the selected failed transaction's watchdog.
func (r *Runtime) releaseRecovery(ctx context.Context, b []byte) (any, error) {
	var q struct {
		ID, Kind string
		Confirm  bool
	}
	if e := decode(b, &q); e != nil {
		return nil, e
	}
	if !q.Confirm || !engine.ID(q.ID) {
		return nil, errors.New("explicit_recovery_release_required")
	}
	folder := ""
	switch q.Kind {
	case "config":
		folder = "changes"
	case "certificate":
		folder = "certificate-transactions"
	case "logging":
		folder = "log-transactions"
	default:
		return nil, errors.New("invalid_recovery_kind")
	}
	path := r.file(folder, q.ID+".json")
	raw, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return map[string]any{"released": true, "files_changed": false, "already_absent": true}, nil
	}
	if e != nil {
		return nil, e
	}
	var journal map[string]any
	if json.Unmarshal(raw, &journal) != nil {
		return nil, errors.New("recovery_journal_unreadable")
	}
	journal["Phase"] = "released"
	if _, ok := journal["phase"]; ok {
		journal["phase"] = "released"
	}
	if e = writeJSON(path, journal); e != nil {
		return nil, e
	}
	r.clearTimer(ctx, q.ID)
	return map[string]any{"released": true, "files_changed": false, "processes_changed": false, "backups_preserved": true}, nil
}
