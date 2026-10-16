package nodeops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/itsHesamHoseini/TunnelManager/internal/protocol"
)

type RecoveryPolicy struct {
	ID               string     `json:"id"`
	Enabled          bool       `json:"enabled"`
	CPU              float64    `json:"cpu"`
	RAM              uint64     `json:"ram"`
	SustainedSeconds int        `json:"sustained_seconds"`
	CooldownSeconds  int        `json:"cooldown_seconds"`
	DailyLimit       int        `json:"daily_limit"`
	Since            *time.Time `json:"since,omitempty"`
	Last             *time.Time `json:"last,omitempty"`
	Day              string     `json:"day"`
	Count            int        `json:"count"`
	Reason           string     `json:"reason"`
}

func (r *Runtime) recoveryPolicy(ctx context.Context, b []byte) (any, error) {
	var q RecoveryPolicy
	if e := decode(b, &q); e != nil {
		return nil, e
	}
	if _, e := r.load(q.ID); e != nil {
		return nil, e
	}
	if q.CPU < 0 || q.CPU > 6400 || q.SustainedSeconds < 60 || q.SustainedSeconds > 3600 || q.CooldownSeconds < 120 || q.DailyLimit < 1 || q.DailyLimit > 10 || q.CPU == 0 && q.RAM == 0 {
		return nil, errors.New("invalid_recovery_thresholds")
	}
	if old, e := os.ReadFile(r.file("recovery", q.ID+".json")); e == nil {
		var p RecoveryPolicy
		if json.Unmarshal(old, &p) == nil {
			q.Last = p.Last
			q.Day = p.Day
			q.Count = p.Count
		}
	}
	q.Since = nil
	if e := writeJSON(r.file("recovery", q.ID+".json"), q); e != nil {
		return nil, e
	}
	return q, nil
}
func (r *Runtime) Observe(ctx context.Context, data protocol.Telemetry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	unlock, e := mutationLock(ctx, r.file("mutation.lock"))
	if e != nil {
		return
	}
	defer unlock()
	entries, _ := os.ReadDir(r.file("recovery"))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := r.file("recovery", entry.Name())
		b, e := os.ReadFile(path)
		var p RecoveryPolicy
		if e != nil || json.Unmarshal(b, &p) != nil || !p.Enabled {
			continue
		}
		v, e := r.load(p.ID)
		if e != nil || v.Stopped || v.Disabled {
			continue
		}
		pidData, e := run(ctx, "systemctl", "show", v.Unit, "--property=MainPID", "--value")
		if e != nil {
			continue
		}
		pid := 0
		fmt.Sscan(string(pidData), &pid)
		var process *protocol.Process
		for i := range data.Processes {
			if data.Processes[i].PID == pid {
				process = &data.Processes[i]
				break
			}
		}
		if process == nil {
			continue
		}
		now := time.Now()
		high := (p.CPU > 0 && process.CPU != nil && *process.CPU >= p.CPU) || (p.RAM > 0 && process.RAM >= p.RAM)
		if !high {
			p.Since = nil
		} else if p.Since == nil {
			p.Since = &now
		}
		day := now.UTC().Format("2006-01-02")
		if p.Day != day {
			p.Day = day
			p.Count = 0
		}
		if p.Since != nil && now.Sub(*p.Since) >= time.Duration(p.SustainedSeconds)*time.Second && (p.Last == nil || now.Sub(*p.Last) >= time.Duration(p.CooldownSeconds)*time.Second) && p.Count < p.DailyLimit {
			if _, e = registryRawCheck(r, p.ID); e == nil {
				if _, e = run(ctx, "systemctl", "restart", "--", v.Unit); e == nil {
					p.Count++
					p.Last = &now
					p.Since = nil
					p.Reason = "sustained_process_resource_threshold"
					writeJSON(r.file("events", now.UTC().Format("20060102T150405.000000000")+".json"), map[string]any{"at": now, "instance": p.ID, "action": "recovery-restart", "reason": p.Reason, "daily_count": p.Count})
				}
			}
		}
		writeJSON(path, p)
	}
}
func registryRawCheck(r *Runtime, id string) (string, error) {
	_, raw, e := registryRaw(r, id)
	return raw, e
}
func (r *Runtime) RecoveryEvents() []map[string]any {
	out := []map[string]any{}
	entries, _ := os.ReadDir(r.file("events"))
	for _, v := range entries {
		if len(out) >= 50 {
			break
		}
		b, e := os.ReadFile(filepath.Join(r.file("events"), v.Name()))
		var row map[string]any
		if e == nil && json.Unmarshal(b, &row) == nil {
			out = append(out, row)
		}
	}
	return out
}
