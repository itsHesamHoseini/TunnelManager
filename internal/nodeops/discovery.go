package nodeops

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
)

type Discovered struct {
	Linked   bool            `json:"linked"`
	Recovery *RecoveryPolicy `json:"recovery,omitempty"`
	Instance
	Parsed        engine.Parsed `json:"parsed"`
	Active        string        `json:"active"`
	Enabled       string        `json:"enabled"`
	Fingerprint   string        `json:"fingerprint"`
	Configuration string        `json:"configuration"`
	AuthMatch     string        `json:"auth_match"`
	Reason        string        `json:"reason,omitempty"`
}

func instanceID(unit string) string { return engine.Digest([]byte(unit))[:24] }

var unitRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@:-]{0,160}\.service$`)
var execRE = regexp.MustCompile(`path=([^ ;]+).*?argv\[\]=(.+?) ;`)

func (r *Runtime) Inventory(ctx context.Context, key []byte) (any, error) {
	if e := native(); e != nil {
		return nil, e
	}
	b, e := run(ctx, "systemctl", "show", "--type=service", "--all", "--property=Id,MainPID,ExecStart,ActiveState,UnitFileState")
	if e != nil {
		return nil, e
	}
	items := []Discovered{}
	owned := map[string]Instance{}
	entries, _ := os.ReadDir(r.file("instances"))
	for _, entry := range entries {
		var v Instance
		raw, e := os.ReadFile(r.file("instances", entry.Name()))
		if e == nil && json.Unmarshal(raw, &v) == nil && v.Managed {
			owned[v.Unit] = v
		}
	}
	for _, block := range strings.Split(string(b), "\n\n") {
		props := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			k, v, ok := strings.Cut(line, "=")
			if ok {
				props[k] = v
			}
		}
		unit := props["Id"]
		if !unitRE.MatchString(unit) {
			continue
		}
		exe := ""
		args := []string{}
		if pid, e := strconv.Atoi(props["MainPID"]); e == nil && pid > 0 {
			exe, _ = os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
			if argv, e := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); e == nil {
				args = strings.Split(strings.TrimRight(string(argv), "\x00"), "\x00")
			}
		}
		if exe == "" {
			if match := execRE.FindStringSubmatch(props["ExecStart"]); len(match) == 3 {
				exe = match[1]
				args = strings.Fields(match[2])
			}
		}
		name := ""
		lower := strings.ToLower(filepath.Base(exe))
		if strings.Contains(lower, "backhaul") {
			name = "backhaul"
		} else if strings.Contains(lower, "rathole") {
			name = "rathole"
		}
		if name == "" {
			continue
		}
		path := ""
		for i, arg := range args {
			if (arg == "-c" || arg == "--config") && i+1 < len(args) {
				path = args[i+1]
			}
			if name == "rathole" && strings.HasSuffix(arg, ".toml") {
				path = arg
			}
		}
		d := Discovered{Instance: Instance{ID: instanceID(unit), Name: strings.TrimSuffix(unit, ".service"), Engine: name, Unit: unit, Binary: exe, Path: path}, Active: props["ActiveState"], Enabled: props["UnitFileState"]}
		if definition, e := run(ctx, "systemctl", "cat", "--", unit); e == nil {
			d.DefinitionHash = engine.Digest(definition)
		}
		if !filepath.IsAbs(path) || !strings.HasSuffix(path, ".toml") {
			d.Reason = "config_path_not_resolved"
			items = append(items, d)
			continue
		}
		raw, e := readRegular(path, 65536)
		if e != nil {
			d.Reason = "config_unreadable"
			items = append(items, d)
			continue
		}
		d.Hash = engine.Digest(raw)
		p, e := engine.ParseConfiguration(string(raw), name)
		if e != nil {
			d.Reason = "config_unsupported"
		} else {
			d.Parsed = p
			d.Role = p.Role
			d.Routes = engine.SortedRouteIDs(engine.Spec{Routes: p.Routes})
			d.Configuration = engine.Redact(string(raw))
			if len(key) == 32 && p.Token != "" {
				mac := hmac.New(sha256.New, key)
				mac.Write([]byte(p.Token))
				d.AuthMatch = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
			}
			d.Reason = p.Reason
		}
		if binary, e := readRegular(exe, 64*1024*1024); e == nil {
			d.Fingerprint = engine.Digest(binary)
			for _, a := range engine.Catalog {
				if a.Engine == name {
					pinned, e := os.ReadFile(filepath.Join("/opt/tunnelmanager/engines", name, a.Version, name))
					if e == nil && engine.Digest(pinned) == d.Fingerprint {
						d.Version = a.Version
						break
					}
				}
			}
		}
		if own, ok := owned[unit]; ok && own.Path == path && own.Binary == exe {
			d.ID = own.ID
			if own.Name != "" {
				d.Name = own.Name
			}
			d.Managed = true
			d.Adopted = own.Adopted
			d.Stopped = own.Stopped
			d.Disabled = own.Disabled
			var policy RecoveryPolicy
			if b, e := os.ReadFile(r.file("recovery", own.ID+".json")); e == nil && json.Unmarshal(b, &policy) == nil {
				d.Recovery = &policy
			}
		}
		if d.Version == "" && d.Reason == "" {
			d.Reason = "install_verified_version_before_adoption"
		}
		items = append(items, d)
		if len(items) >= 100 {
			break
		}
	}
	addresses := []string{}
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			host, _, _ := strings.Cut(a.String(), "/")
			addresses = append(addresses, host)
		}
	}
	return map[string]any{"instances": items, "addresses": addresses, "scope": "systemd engine instances; configs read only; unrecognized paths remain unresolved"}, nil
}
func readRegular(path string, max int64) ([]byte, error) {
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Size() > max || st.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("protected_file_unavailable")
	}
	return os.ReadFile(path)
}
func (r *Runtime) adopt(ctx context.Context, b []byte) (any, error) {
	var q struct {
		ID, Hash, Fingerprint, DefinitionHash string
		Confirm                               bool
	}
	if e := decode(b, &q); e != nil {
		return nil, e
	}
	if !q.Confirm {
		return nil, errors.New("explicit_adoption_required")
	}
	data, e := r.Inventory(ctx, nil)
	if e != nil {
		return nil, e
	}
	for _, d := range data.(map[string]any)["instances"].([]Discovered) {
		if d.ID != q.ID {
			continue
		}
		if d.Hash != q.Hash || d.Fingerprint != q.Fingerprint || d.DefinitionHash == "" || d.DefinitionHash != q.DefinitionHash {
			return nil, errors.New("discovery_drift")
		}
		if d.Version == "" || d.Reason != "" {
			return nil, errors.New("unsupported_instance_requires_verified_binary")
		}
		v := d.Instance
		v.Managed = true
		v.Adopted = true
		v.Stopped = d.Active != "active"
		v.Disabled = d.Enabled != "enabled"
		if e = r.save(v); e != nil {
			return nil, e
		}
		raw, e := readRegular(v.Path, 65536)
		if e != nil {
			return nil, e
		}
		return map[string]any{"adopted": true, "instance": v, "private_configuration": string(raw)}, nil
	}
	return nil, errors.New("discovered_instance_missing")
}
func registryRaw(r *Runtime, id string) (Instance, string, error) {
	v, e := r.load(id)
	if e != nil {
		return v, "", e
	}
	b, e := readRegular(v.Path, 65536)
	if e != nil {
		return v, "", e
	}
	if engine.Digest(b) != v.Hash {
		return v, "", errors.New("manual_config_drift")
	}
	if v.UnitPath != "" {
		unit, e := readRegular(v.UnitPath, 65536)
		if e != nil || engine.Digest(unit) != v.UnitHash {
			return v, "", errors.New("manual_unit_drift")
		}
	}
	if v.DefinitionHash != "" {
		ctx, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		definition, e := run(ctx, "systemctl", "cat", "--", v.Unit)
		if e != nil || engine.Digest(definition) != v.DefinitionHash {
			return v, "", errors.New("manual_unit_drift")
		}
	}
	return v, string(b), nil
}
func decodeMap(v any) map[string]any {
	b, _ := json.Marshal(v)
	m := map[string]any{}
	json.Unmarshal(b, &m)
	return m
}
