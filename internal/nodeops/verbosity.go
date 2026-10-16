package nodeops

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/itsHesamHoseini/TunnelManager/internal/config"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"github.com/pelletier/go-toml/v2"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type logTransaction struct {
	ID, Phase, Path, Hash string
	Instance              Instance
	Old, New              []byte
	Existed, Active       bool
	Deadline              time.Time
}

func (r *Runtime) logSession(instance string) *logTransaction {
	entries, _ := os.ReadDir(r.file("log-transactions"))
	for _, entry := range entries {
		var j logTransaction
		b, e := os.ReadFile(r.file("log-transactions", entry.Name()))
		if e == nil && json.Unmarshal(b, &j) == nil && j.Instance.ID == instance && j.Phase != "reverted" && j.Phase != "released" {
			return &j
		}
	}
	return nil
}
func (r *Runtime) verbosity(ctx context.Context, b []byte) (any, error) {
	var q struct {
		ID, Session, Level, ExpectedHash string
		Seconds                          int
		Restore, Confirm                 bool
	}
	if e := decode(b, &q); e != nil {
		return nil, e
	}
	if !q.Confirm || !engine.ID(q.Session) || len(q.Session) > 59 {
		return nil, errors.New("confirm_temporary_logging")
	}
	id := "log_" + q.Session
	if q.Restore {
		var j logTransaction
		data, e := os.ReadFile(r.file("log-transactions", id+".json"))
		if e != nil || json.Unmarshal(data, &j) != nil || j.Instance.ID != q.ID {
			return nil, errors.New("logging_session_missing")
		}
		return map[string]any{"restored": true}, r.restoreLogging(ctx, id)
	}
	if q.Level != "debug" && q.Level != "trace" || q.Seconds < 60 || q.Seconds > 600 {
		return nil, errors.New("logging_level_or_duration_invalid")
	}
	if e := r.pending(q.ID, ""); e != nil {
		return nil, e
	}
	v, raw, e := registryRaw(r, q.ID)
	if e != nil {
		return nil, e
	}
	if v.Hash != q.ExpectedHash {
		return nil, errors.New("config_revision_conflict")
	}
	j := logTransaction{ID: id, Instance: v, Deadline: time.Now().Add(time.Duration(q.Seconds) * time.Second), Phase: "prepared", Active: isState(ctx, "is-active", v.Unit, "active")}
	if v.Engine == "backhaul" {
		m, e := engine.Parse(raw)
		if e != nil {
			return nil, e
		}
		side, _ := m[v.Role].(map[string]any)
		if side == nil {
			return nil, errors.New("config_role_missing")
		}
		side["log_level"] = q.Level
		j.New, e = toml.Marshal(m)
		if e != nil {
			return nil, e
		}
		j.Path = v.Path
		j.Old = []byte(raw)
		j.Existed = true
	} else if v.Engine == "rathole" {
		j.Path = filepath.Join("/etc/systemd/system", v.Unit+".d", "95-tunnelmanager-logging.conf")
		j.Old, e = os.ReadFile(j.Path)
		j.Existed = e == nil
		if e != nil && !os.IsNotExist(e) {
			return nil, e
		}
		j.New = []byte("[Service]\nEnvironment=RUST_LOG=" + q.Level + "\n")
	} else {
		return nil, errors.New("unsupported_logging_engine")
	}
	j.Hash = engine.Digest(j.New)
	if e = writeJSON(r.file("log-transactions", id+".json"), j); e != nil {
		return nil, e
	}
	if e = r.armRollback(ctx, Journal{Change: Change{ID: id, Deadline: j.Deadline}}); e != nil {
		return nil, e
	}
	j.Phase = "applying"
	if e = writeJSON(r.file("log-transactions", id+".json"), j); e != nil {
		return nil, e
	}
	if e = config.Atomic(j.Path, j.New, 0600); e != nil {
		return nil, e
	}
	if _, e = run(ctx, "systemctl", "daemon-reload"); e != nil {
		return nil, e
	}
	if v.Engine == "backhaul" {
		v.Hash = j.Hash
	}
	v.Epoch = id
	definition, e := run(ctx, "systemctl", "cat", "--", v.Unit)
	if e != nil {
		return nil, e
	}
	v.DefinitionHash = engine.Digest(definition)
	if e = r.save(v); e != nil {
		return nil, e
	}
	if j.Active && !v.Stopped {
		if _, e = run(ctx, "systemctl", "restart", "--", v.Unit); e != nil {
			return nil, errors.New("logging_restart_failed_local_restore_armed")
		}
	}
	j.Phase = "active"
	if e = writeJSON(r.file("log-transactions", id+".json"), j); e != nil {
		return nil, e
	}
	return map[string]any{"session": q.Session, "until": j.Deadline, "level": q.Level, "scope": "selected service; local timer restores configuration even without controller"}, nil
}
func (r *Runtime) restoreLogging(ctx context.Context, id string) error {
	if !engine.ID(id) || !strings.HasPrefix(id, "log_") {
		return errors.New("invalid_logging_session")
	}
	var j logTransaction
	b, e := os.ReadFile(r.file("log-transactions", id+".json"))
	if e != nil || json.Unmarshal(b, &j) != nil || j.ID != id {
		return errors.New("logging_session_missing")
	}
	if j.Phase == "reverted" || j.Phase == "released" {
		return nil
	}
	if j.Phase != "prepared" {
		raw, e := os.ReadFile(j.Path)
		if e != nil || (engine.Digest(raw) != j.Hash && string(raw) != string(j.Old)) {
			return errors.New("manual_logging_drift")
		}
		v, e := r.load(j.Instance.ID)
		if e != nil {
			return e
		}
		if j.Phase == "active" {
			if _, _, e = registryRaw(r, v.ID); e != nil {
				return e
			}
		}
		if v.Epoch != id && !strings.HasPrefix(v.Epoch, "intent_") && !(j.Phase == "applying" && v.Epoch == j.Instance.Epoch) {
			return errors.New("newer_change_blocks_logging_restore")
		}
		if j.Existed {
			e = config.Atomic(j.Path, j.Old, 0600)
		} else {
			e = os.Remove(j.Path)
		}
		if e != nil {
			return e
		}
		if _, e = run(ctx, "systemctl", "daemon-reload"); e != nil {
			return e
		}
		original := j.Instance
		original.Stopped = v.Stopped
		original.Disabled = v.Disabled
		if v.Epoch != id {
			original.Epoch = v.Epoch
		}
		if e = r.save(original); e != nil {
			return e
		}
		if j.Active && !v.Stopped {
			if _, e = run(ctx, "systemctl", "restart", "--", v.Unit); e != nil {
				return e
			}
		}
	}
	j.Phase = "reverted"
	if e = writeJSON(r.file("log-transactions", id+".json"), j); e != nil {
		return e
	}
	r.clearTimer(ctx, id)
	return nil
}
