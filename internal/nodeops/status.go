package nodeops

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (r *Runtime) resolve(ctx context.Context, id string) (Instance, error) {
	if !engine.ID(id) {
		return Instance{}, errors.New("invalid_instance_id")
	}
	if v, e := r.load(id); e == nil {
		return v, nil
	}
	data, e := r.Inventory(ctx, nil)
	if e != nil {
		return Instance{}, e
	}
	for _, d := range data.(map[string]any)["instances"].([]Discovered) {
		if d.ID == id {
			return d.Instance, nil
		}
	}
	return Instance{}, errors.New("instance_missing_rediscover")
}
func (r *Runtime) status(ctx context.Context, b []byte) (any, error) {
	var q struct{ ID string }
	if e := decode(b, &q); e != nil {
		return nil, e
	}
	v, e := r.resolve(ctx, q.ID)
	if e != nil {
		return nil, e
	}
	out := map[string]any{"instance": v.ID, "unit": v.Unit, "at": time.Now().UTC(), "active": isState(ctx, "is-active", v.Unit, "active"), "enabled": isState(ctx, "is-enabled", v.Unit, "enabled"), "intentional_stop": v.Stopped || v.Disabled, "scope": "selected systemd unit; not full tunnel health"}
	raw, e := readRegular(v.Path, 65536)
	out["drift"] = e != nil || engine.Digest(raw) != v.Hash
	var p RecoveryPolicy
	if b, e := os.ReadFile(r.file("recovery", v.ID+".json")); e == nil && json.Unmarshal(b, &p) == nil {
		out["recovery"] = p
	}
	return out, nil
}
func (r *Runtime) tools(ctx context.Context, b []byte) (any, error) {
	var q struct{}
	if e := decode(b, &q); e != nil {
		return nil, e
	}
	out := map[string]any{"at": time.Now().UTC(), "scope": "host firewall observations; external reachability checked separately"}
	for name, args := range map[string][]string{"ufw": {"status", "numbered"}, "nft": {"list", "ruleset"}} {
		if raw, e := run(ctx, name, args...); e == nil {
			if len(raw) > 32768 {
				raw = raw[:32768]
			}
			out[name] = redactLog(string(raw))
		} else {
			out[name] = "unavailable"
		}
	}
	certs := []map[string]any{}
	dirs, _ := os.ReadDir(filepath.Join(r.ConfigDir, "certificates"))
	for _, dir := range dirs {
		if !dir.IsDir() || !engine.ID(dir.Name()) {
			continue
		}
		raw, e := os.ReadFile(filepath.Join(r.ConfigDir, "certificates", dir.Name(), "cert.pem"))
		if e == nil {
			certs = append(certs, map[string]any{"id": dir.Name(), "hash": engine.Digest(raw)})
		}
		if len(certs) >= 100 {
			break
		}
	}
	out["certificates"] = certs
	out["recovery_events"] = r.RecoveryEvents()
	return out, nil
}
func rawSecrets(raw string) []string {
	m, e := engine.Parse(raw)
	if e != nil {
		return nil
	}
	out := []string{}
	var walk func(map[string]any)
	walk = func(v map[string]any) {
		for k, value := range v {
			if child, ok := value.(map[string]any); ok {
				walk(child)
			} else if s, ok := value.(string); ok && (strings.Contains(k, "token") || strings.Contains(k, "password") || strings.Contains(k, "private_key")) {
				if len(s) > 0 {
					out = append(out, s)
				}
			}
		}
	}
	walk(m)
	return out
}
