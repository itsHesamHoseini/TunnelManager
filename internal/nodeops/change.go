package nodeops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/itsHesamHoseini/TunnelManager/internal/config"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
)

type Change struct {
	ID           string      `json:"id"`
	Instance     string      `json:"instance"`
	Name         string      `json:"name"`
	Role         string      `json:"role"`
	ExpectedHash string      `json:"expected_hash"`
	Spec         engine.Spec `json:"spec"`
	Deadline     time.Time   `json:"deadline"`
}
type Journal struct {
	Change      Change    `json:"change"`
	Old         *Instance `json:"old,omitempty"`
	OldUnit     []byte    `json:"old_unit,omitempty"`
	NewUnit     []byte    `json:"new_unit,omitempty"`
	UnitExisted bool      `json:"unit_existed"`
	UnitPath    string    `json:"unit_path"`
	Candidate   Instance  `json:"candidate"`
	NewConfig   string    `json:"new_config"`
	Phase       string    `json:"phase"`
	WasActive   bool      `json:"was_active"`
	WasEnabled  bool      `json:"was_enabled"`
}

func (r *Runtime) preflight(ctx context.Context, b []byte) (any, error) {
	var q Change
	if e := decode(b, &q); e != nil {
		return nil, e
	}
	if e := r.pending(q.Instance, q.ID); e != nil {
		return nil, e
	}
	if e := engine.NormalizeRaw(&q.Spec); e != nil {
		return nil, e
	}
	if q.Spec.Certificate != "" {
		if e := r.pendingCertificate(q.Spec.Certificate, q.ID); e != nil {
			return nil, e
		}
	}
	if !engine.ID(q.ID) || !engine.ID(q.Instance) {
		return nil, errors.New("invalid_change_identity")
	}
	if e := engine.Validate(q.Spec); e != nil {
		return nil, e
	}
	raw, e := r.render(q.Spec, q.Role)
	if e != nil {
		return nil, e
	}
	_ = raw
	binary := filepath.Join("/opt/tunnelmanager/engines", q.Spec.Engine, q.Spec.Version, q.Spec.Engine)
	if _, e := os.Stat(binary); e != nil {
		return nil, errors.New("install_selected_engine_first")
	}
	if a, e := engine.ArtifactFor(q.Spec.Engine, q.Spec.Version, runtime.GOARCH); e != nil || !verifiedBinary(binary, a) {
		return nil, errors.New("installed_engine_binary_changed_reinstall_verified_version")
	}
	var old *Instance
	if v, e := r.load(q.Instance); e == nil {
		old = &v
		if _, _, e = registryRaw(r, q.Instance); e != nil {
			return nil, e
		}
		if q.ExpectedHash == "" || q.ExpectedHash != v.Hash {
			return nil, errors.New("config_revision_conflict")
		}
	}
	issues := []map[string]any{}
	published, dockerError := dockerPorts(ctx)
	if dockerError != nil {
		issues = append(issues, map[string]any{"code": dockerError.Error()})
	}
	for _, bind := range engine.Bindings(q.Spec, q.Role) {
		if dockerConflict(published, bind) {
			issues = append(issues, map[string]any{"code": "docker_published_port_conflict", "address": net.JoinHostPort(bind.Host, fmt.Sprint(bind.Port)), "protocol": bind.Protocol})
			continue
		}
		address := net.JoinHostPort(bind.Host, fmt.Sprint(bind.Port))
		if bind.Host == "*" {
			address = net.JoinHostPort("", fmt.Sprint(bind.Port))
		}
		if probeBinding(bind) == nil {
			continue
		}
		allowed := false
		if old != nil {
			if current, e := os.ReadFile(old.Path); e == nil {
				p, e := engine.ParseConfiguration(string(current), old.Engine)
				if e == nil {
					existing := []engine.Binding{}
					if v, e := engine.ParseEndpoint(p.Bind); e == nil {
						existing = append(existing, engine.Binding{Host: v.Host, Port: v.Port, Protocol: "tcp"})
					}
					for _, route := range p.Routes {
						existing = append(existing, engine.Binding{Host: route.User.Host, Port: route.User.Port, Protocol: route.Protocol})
					}
					for _, v := range existing {
						if engine.Conflict(bind, v) {
							allowed = ownedListener(ctx, old.Unit, bind)
						}
					}
				}
			}
		}
		if !allowed {
			issues = append(issues, map[string]any{"code": "port_occupied_or_address_unavailable", "address": address, "protocol": bind.Protocol})
		}
	}
	if q.Role == "client" {
		for _, route := range q.Spec.Routes {
			if route.Protocol == "udp" {
				continue
			}
			d := net.Dialer{Timeout: 2 * time.Second}
			conn, e := d.DialContext(ctx, "tcp", route.Backend.String())
			if e != nil {
				issues = append(issues, map[string]any{"code": "backend_unreachable", "endpoint": route.Backend.String()})
			} else {
				conn.Close()
			}
		}
	}
	if q.Spec.Certificate != "" {
		if cert, e := os.ReadFile(filepath.Join(r.ConfigDir, "certificates", q.Spec.Certificate, "cert.pem")); e != nil {
			issues = append(issues, map[string]any{"code": "certificate_not_deployed"})
		} else if q.Spec.CertificateHash != "" && engine.Digest(cert) != q.Spec.CertificateHash {
			issues = append(issues, map[string]any{"code": "selected_certificate_revision_not_deployed"})
		}
	}
	current := ""
	if old != nil {
		b, _ := os.ReadFile(old.Path)
		current = engine.Redact(string(b))
	}
	return map[string]any{"valid": len(issues) == 0, "issues": issues, "current": current, "configuration": engine.Redact(raw), "scope": "local bind and selected backend checks; external firewall reachability requires peer diagnostics"}, nil
}
func (r *Runtime) prepare(ctx context.Context, b []byte) (any, error) {
	var q Change
	if e := decode(b, &q); e != nil {
		return nil, e
	}
	if !q.Deadline.After(time.Now()) || q.Deadline.After(time.Now().Add(10*time.Minute)) {
		return nil, errors.New("invalid_confirmation_deadline")
	}
	if e := engine.NormalizeRaw(&q.Spec); e != nil {
		return nil, e
	}
	p, e := r.preflight(ctx, b)
	if e != nil {
		return nil, e
	}
	if !p.(map[string]any)["valid"].(bool) {
		return p, errors.New("preflight_blocked")
	}
	path := r.file("changes", q.ID+".json")
	if _, e := os.Stat(path); e == nil {
		return nil, errors.New("change_already_prepared")
	}
	raw, e := r.render(q.Spec, q.Role)
	if e != nil {
		return nil, e
	}
	v := Instance{ID: q.Instance, Name: q.Name, Engine: q.Spec.Engine, Version: q.Spec.Version, Role: q.Role, Unit: "tunnelmanager-instance-" + q.Instance + ".service", Path: filepath.Join(r.ConfigDir, "instances", q.Instance+".toml"), Binary: filepath.Join("/opt/tunnelmanager/engines", q.Spec.Engine, q.Spec.Version, q.Spec.Engine), Hash: engine.Digest([]byte(raw)), Managed: true, Routes: engine.SortedRouteIDs(q.Spec)}
	j := Journal{Change: q, Candidate: v, NewConfig: raw, Phase: "prepared"}
	j.Candidate.Epoch = q.ID
	if old, e := r.load(q.Instance); e == nil {
		if _, _, e = registryRaw(r, q.Instance); e != nil {
			return nil, e
		}
		backup, e := os.ReadFile(old.Path)
		if e != nil {
			return nil, e
		}
		if e = config.Atomic(r.file("backups", q.ID+".toml"), backup, 0600); e != nil {
			return nil, e
		}
		j.Old = &old
		v.Unit = old.Unit
		if old.Name != "" {
			v.Name = old.Name
		}
		v.Adopted = old.Adopted
		v.Stopped = old.Stopped
		v.Disabled = old.Disabled
		j.Candidate = v
		j.Candidate.Epoch = q.ID
		j.WasActive = isState(ctx, "is-active", old.Unit, "active")
		j.WasEnabled = isState(ctx, "is-enabled", old.Unit, "enabled")
	}
	if j.Old != nil && j.Old.Adopted {
		j.UnitPath = filepath.Join("/etc/systemd/system", v.Unit+".d", "90-tunnelmanager.conf")
	} else {
		j.UnitPath = filepath.Join("/etc/systemd/system", v.Unit)
	}
	if old, e := os.ReadFile(j.UnitPath); e == nil {
		j.OldUnit = old
		j.UnitExisted = true
	}
	if e = writeJSON(path, j); e != nil {
		return nil, e
	}
	return map[string]any{"prepared": true, "instance": q.Instance}, nil
}
func (r *Runtime) render(spec engine.Spec, role string) (string, error) {
	raw, e := engine.Render(spec, role)
	if e != nil {
		return "", e
	}
	return strings.ReplaceAll(raw, "/etc/tunnelmanager-agent/certificates/", filepath.ToSlash(filepath.Join(r.ConfigDir, "certificates"))+"/"), nil
}
func isState(ctx context.Context, action, unit, expected string) bool {
	b, e := run(ctx, "systemctl", action, "--", unit)
	return e == nil && strings.TrimSpace(string(b)) == expected
}
func (r *Runtime) journal(id string) (Journal, error) {
	if !engine.ID(id) {
		return Journal{}, errors.New("invalid_change_id")
	}
	b, e := os.ReadFile(r.file("changes", id+".json"))
	var j Journal
	if e != nil || json.Unmarshal(b, &j) != nil {
		return j, errors.New("change_journal_missing")
	}
	return j, nil
}
func (r *Runtime) activate(ctx context.Context, b []byte) (any, error) {
	var q struct {
		ID       string
		Deadline time.Time
	}
	if e := decode(b, &q); e != nil {
		return nil, e
	}
	j, e := r.journal(q.ID)
	if e != nil {
		return nil, e
	}
	if j.Phase != "prepared" {
		return nil, errors.New("change_not_prepared")
	}
	if j.Change.Deadline.Before(time.Now()) {
		return nil, errors.New("preparation_expired_recheck_before_applying")
	}
	if !q.Deadline.IsZero() {
		if !q.Deadline.After(time.Now()) || q.Deadline.After(time.Now().Add(95*time.Second)) {
			return nil, errors.New("invalid_activation_deadline")
		}
		j.Change.Deadline = q.Deadline
	}
	if time.Until(j.Change.Deadline) < 10*time.Second {
		return nil, errors.New("confirmation_deadline_too_close")
	}
	if j.Old != nil {
		if _, _, e = registryRaw(r, j.Old.ID); e != nil {
			return nil, e
		}
	}
	check, _ := json.Marshal(j.Change)
	preview, e := r.preflight(ctx, check)
	if e != nil {
		return nil, e
	}
	if valid, _ := preview.(map[string]any)["valid"].(bool); !valid {
		return preview, errors.New("preflight_changed_before_activation")
	}
	if e = r.armRollback(ctx, j); e != nil {
		return nil, e
	}
	j.Phase = "activating"
	if e = writeJSON(r.file("changes", q.ID+".json"), j); e != nil {
		return nil, e
	}
	if e = config.Atomic(j.Candidate.Path, []byte(j.NewConfig), 0600); e != nil {
		return nil, e
	}
	var unit string
	if j.Old != nil && j.Old.Adopted {
		unit = "[Service]\nExecStart=\nExecStart=" + j.Candidate.Binary + " -c " + j.Candidate.Path + "\n"

	} else {
		args := " -c "

		unit = "[Unit]\nDescription=TunnelManager managed tunnel instance\nAfter=network-online.target\n[Service]\nType=simple\nExecStart=" + j.Candidate.Binary + args + j.Candidate.Path + "\nRestart=no\nUMask=0077\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\nProtectKernelTunables=true\nProtectControlGroups=true\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nRestrictAddressFamilies=AF_INET AF_INET6\nMemoryMax=256M\nTasksMax=256\nInaccessiblePaths=-" + r.ConfigDir + "/identity.key -" + r.ConfigDir + "/node.json -/etc/tunnelmanager -/var/lib/tunnelmanager-agent\n[Install]\nWantedBy=multi-user.target\n"
	}
	j.NewUnit = []byte(unit)
	if e = writeJSON(r.file("changes", q.ID+".json"), j); e != nil {
		return nil, e
	}
	if e = config.Atomic(j.UnitPath, []byte(unit), 0644); e != nil {
		return nil, e
	}
	if _, e = run(ctx, "systemctl", "daemon-reload"); e != nil {
		return nil, e
	}
	if !j.Candidate.Disabled {
		if _, e = run(ctx, "systemctl", "enable", "--", j.Candidate.Unit); e != nil {
			return nil, e
		}
	}
	if !j.Candidate.Stopped {
		if _, e = run(ctx, "systemctl", "restart", "--", j.Candidate.Unit); e != nil {
			r.rollback(context.Background(), q.ID)
			return nil, e
		}
	}
	j.Candidate.UnitPath = j.UnitPath
	j.Candidate.UnitHash = engine.Digest([]byte(unit))
	definition, definitionError := run(ctx, "systemctl", "cat", "--", j.Candidate.Unit)
	if definitionError != nil {
		return nil, definitionError
	}
	j.Candidate.DefinitionHash = engine.Digest(definition)
	if e = r.save(j.Candidate); e != nil {
		return nil, e
	}
	j.Phase = "awaiting_confirmation"
	writeJSON(r.file("changes", q.ID+".json"), j)
	return map[string]any{"activated": true, "deadline": j.Change.Deadline, "instance": j.Candidate, "process_active": isState(ctx, "is-active", j.Candidate.Unit, "active")}, nil
}
func (r *Runtime) armRollback(ctx context.Context, j Journal) error {
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	base := "tunnelmanager-rollback-" + j.Change.ID
	service := "[Unit]\nDescription=TunnelManager local change rollback\nStartLimitIntervalSec=900\nStartLimitBurst=3\n[Service]\nType=oneshot\nRestart=on-failure\nRestartSec=10\nTimeoutStartSec=125\nExecStart=" + exe + " local-rollback --id " + j.Change.ID + " --config-dir " + r.ConfigDir + "\n"
	timer := "[Unit]\nDescription=TunnelManager confirmation deadline\n[Timer]\nOnCalendar=" + j.Change.Deadline.UTC().Format("2006-01-02 15:04:05 UTC") + "\nPersistent=true\nAccuracySec=1s\nUnit=" + base + ".service\n[Install]\nWantedBy=timers.target\n"
	for name, data := range map[string]string{base + ".service": service, base + ".timer": timer} {
		if e = config.Atomic(filepath.Join("/etc/systemd/system", name), []byte(data), 0644); e != nil {
			return e
		}
	}
	if _, e = run(ctx, "systemctl", "daemon-reload"); e != nil {
		return e
	}
	_, e = run(ctx, "systemctl", "enable", "--now", "--", base+".timer")
	return e
}
func (r *Runtime) clearTimer(ctx context.Context, id string) {
	base := "tunnelmanager-rollback-" + id
	run(ctx, "systemctl", "disable", "--now", "--", base+".timer")
	os.Remove(filepath.Join("/etc/systemd/system", base+".timer"))
	os.Remove(filepath.Join("/etc/systemd/system", base+".service"))
	run(ctx, "systemctl", "daemon-reload")
}
func (r *Runtime) confirm(ctx context.Context, b []byte) (any, error) {
	var q struct {
		ID     string
		Commit bool
	}
	if e := decode(b, &q); e != nil {
		return nil, e
	}
	j, e := r.journal(q.ID)
	if e != nil {
		return nil, e
	}
	if (j.Phase != "awaiting_confirmation" && j.Phase != "validated") || !j.Change.Deadline.After(time.Now()) {
		return nil, errors.New("confirmation_expired_or_reverted")
	}
	if !j.Candidate.Stopped && !isState(ctx, "is-active", j.Candidate.Unit, "active") {
		return nil, errors.New("process_not_active")
	}
	if _, _, e = registryRaw(r, j.Candidate.ID); e != nil {
		return nil, e
	}
	j.Phase = "validated"
	if q.Commit {
		j.Phase = "confirmed"
	}
	if e = writeJSON(r.file("changes", q.ID+".json"), j); e != nil {
		return nil, e
	}
	if q.Commit {
		r.clearTimer(ctx, q.ID)
	}
	return map[string]any{"confirmed": q.Commit, "validated": true}, nil
}
func (r *Runtime) Rollback(ctx context.Context, id string) error {
	unlock, e := mutationLock(ctx, r.file("mutation.lock"))
	if e != nil {
		return e
	}
	defer unlock()
	if strings.HasPrefix(id, "cert_") {
		return r.restoreCertificate(ctx, id)
	}
	if strings.HasPrefix(id, "log_") {
		return r.restoreLogging(ctx, id)
	}
	return r.rollback(ctx, id)
}
func (r *Runtime) rollback(ctx context.Context, id string) error {
	return r.revert(ctx, id, false)
}
func (r *Runtime) revert(ctx context.Context, id string, compensate bool) error {
	j, e := r.journal(id)
	if e != nil {
		return e
	}
	if j.Phase == "reverted" || j.Phase == "released" || (j.Phase == "confirmed" && !compensate) {
		return nil
	}
	if j.Phase == "confirmed" {
		current, _, checkError := registryRaw(r, j.Candidate.ID)
		if checkError != nil {
			return checkError
		}
		if current.Hash != j.Candidate.Hash || current.Epoch != j.Candidate.Epoch {
			return errors.New("newer_change_blocks_compensation")
		}
	}
	if j.Phase == "prepared" {
		j.Phase = "reverted"
		return writeJSON(r.file("changes", id+".json"), j)
	}
	if j.Phase == "awaiting_confirmation" || j.Phase == "validated" {
		if _, _, e := registryRaw(r, j.Candidate.ID); e != nil {
			return e
		}
	}
	current, err := readRegular(j.Candidate.Path, 65536)
	if err == nil && engine.Digest(current) != engine.Digest([]byte(j.NewConfig)) && !(j.Old != nil && j.Old.Path == j.Candidate.Path && engine.Digest(current) == j.Old.Hash) {
		return errors.New("manual_config_drift")
	}
	if err != nil && j.Phase != "activating" {
		return errors.New("manual_config_drift")
	}
	unit, unitError := readRegular(j.UnitPath, 65536)
	if unitError == nil {
		known := j.UnitExisted && engine.Digest(unit) == engine.Digest(j.OldUnit) || len(j.NewUnit) > 0 && engine.Digest(unit) == engine.Digest(j.NewUnit) || j.Candidate.UnitHash != "" && engine.Digest(unit) == j.Candidate.UnitHash
		if !known {
			return errors.New("manual_unit_drift")
		}
	} else if j.UnitExisted {
		return errors.New("manual_unit_drift")
	}
	run(ctx, "systemctl", "stop", "--", j.Candidate.Unit)
	if j.UnitExisted {
		if e = config.Atomic(j.UnitPath, j.OldUnit, 0644); e != nil {
			return e
		}
	} else {
		os.Remove(j.UnitPath)
	}
	if j.Old != nil {
		if j.Old.Path == j.Candidate.Path {
			oldConfig, e := os.ReadFile(r.file("backups", id+".toml"))
			if e != nil {
				return errors.New("rollback_config_backup_missing")
			}
			if e = config.Atomic(j.Old.Path, oldConfig, 0600); e != nil {
				return e
			}
		}
		if e = r.save(*j.Old); e != nil {
			return e
		}
		if j.Old.Path != j.Candidate.Path {
			os.Remove(j.Candidate.Path)
		}
	} else {
		run(ctx, "systemctl", "disable", "--", j.Candidate.Unit)
		os.Remove(j.Candidate.Path)
		os.Remove(r.file("instances", j.Candidate.ID+".json"))
	}
	if _, e = run(ctx, "systemctl", "daemon-reload"); e != nil {
		return e
	}
	if j.Old != nil {
		action := "disable"
		if j.WasEnabled {
			action = "enable"
		}
		run(ctx, "systemctl", action, "--", j.Old.Unit)
		if j.WasActive {
			if _, e = run(ctx, "systemctl", "start", "--", j.Old.Unit); e != nil {
				return e
			}
		}
	}
	j.Phase = "reverted"
	if e = writeJSON(r.file("changes", id+".json"), j); e != nil {
		return e
	}
	r.clearTimer(ctx, id)
	return nil
}
func (r *Runtime) action(ctx context.Context, b []byte) (any, error) {
	var q struct {
		ID, Action, ExpectedHash string
		Confirm                  bool
	}
	if e := decode(b, &q); e != nil {
		return nil, e
	}
	if !engine.ID(q.ID) || !q.Confirm {
		return nil, errors.New("impact_confirmation_required")
	}
	if e := r.pending(q.ID, ""); e != nil && !(e.Error() == "restore_temporary_logging_before_changing_service" && (q.Action == "stop" || q.Action == "disable")) {
		return nil, e
	}
	v, e := r.load(q.ID)
	if q.Action != "revoke" {
		v, _, e = registryRaw(r, q.ID)
	}
	if e != nil {
		if q.Action == "revoke" {
			return map[string]any{"management_revoked": true, "unit_preserved": true}, nil
		}
		if q.Action == "remove" {
			var tombstone struct{ Hash string }
			data, err := os.ReadFile(r.file("removed", q.ID+".json"))
			if err == nil && json.Unmarshal(data, &tombstone) == nil && tombstone.Hash == q.ExpectedHash {
				return map[string]any{"removed": true, "already_completed": true}, nil
			}
		}
		return nil, e
	}
	expected := q.ExpectedHash == v.Hash
	if j := r.logSession(q.ID); j != nil && (q.Action == "stop" || q.Action == "disable") && q.ExpectedHash == j.Instance.Hash {
		expected = true
	}
	if !expected {
		return nil, errors.New("config_revision_conflict")
	}
	if !strings.Contains("|start|stop|restart|reload|disable|remove|revoke|", "|"+q.Action+"|") {
		return nil, errors.New("unknown_instance_action")
	}
	if !q.Confirm {
		return nil, errors.New("impact_confirmation_required")
	}
	if q.Action == "stop" || q.Action == "disable" {
		v.Stopped = true
		if q.Action == "disable" {
			v.Disabled = true
		}
		v.Epoch = "intent_" + engine.Digest(append(b, []byte(time.Now().UTC().Format(time.RFC3339Nano))...))[:24]
		if e = r.save(v); e != nil {
			return nil, e
		}
	}
	switch q.Action {
	case "stop":
		_, e = run(ctx, "systemctl", "stop", "--", v.Unit)
		v.Stopped = true
	case "disable":
		_, e = run(ctx, "systemctl", "disable", "--now", "--", v.Unit)
		v.Disabled = true
		v.Stopped = true
	case "start":
		_, e = run(ctx, "systemctl", "start", "--", v.Unit)
		v.Stopped = false
	case "restart":
		_, e = run(ctx, "systemctl", "restart", "--", v.Unit)
		v.Stopped = false
	case "reload":
		_, e = run(ctx, "systemctl", "reload", "--", v.Unit)
	case "revoke":
		alias := v
		alias.Managed = false
		if e = writeJSON(r.file("unmanaged", v.ID+".json"), alias); e != nil {
			return nil, e
		}
		if e = os.Remove(r.file("instances", v.ID+".json")); e != nil {
			return nil, e
		}
		os.Remove(r.file("recovery", v.ID+".json"))
		return map[string]any{"management_revoked": true, "unit_preserved": true, "configuration_preserved": true}, nil
	case "remove":
		if v.Adopted {
			return nil, errors.New("adopted_instance_preserved_stop_or_revoke_instead")
		}
		_, e = run(ctx, "systemctl", "disable", "--now", "--", v.Unit)
		if e == nil {
			if e = writeJSON(r.file("removed", v.ID+".json"), map[string]string{"Hash": v.Hash}); e != nil {
				return nil, e
			}
			os.Remove(filepath.Join("/etc/systemd/system", v.Unit))
			os.Remove(v.Path)
			os.Remove(r.file("instances", v.ID+".json"))
			os.Remove(r.file("unmanaged", v.ID+".json"))
			run(ctx, "systemctl", "daemon-reload")
			return map[string]any{"removed": true}, nil
		}
	}
	if e != nil {
		return nil, e
	}
	v.Epoch = "intent_" + engine.Digest(append(b, []byte(time.Now().UTC().Format(time.RFC3339Nano))...))[:24]
	if e = r.save(v); e != nil {
		return nil, e
	}
	return map[string]any{"instance": v, "active": isState(ctx, "is-active", v.Unit, "active"), "scope": "selected managed unit only"}, nil
}

// A second operation cannot supersede a still armed local rollback.
func (r *Runtime) pending(instance, except string) error {
	if j := r.logSession(instance); j != nil && j.ID != except {
		return errors.New("restore_temporary_logging_before_changing_service")
	}
	entries, _ := os.ReadDir(r.file("changes"))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		b, e := os.ReadFile(r.file("changes", entry.Name()))
		var j Journal
		if e == nil && json.Unmarshal(b, &j) == nil && j.Change.Instance == instance && j.Change.ID != except && j.Phase != "confirmed" && j.Phase != "reverted" && j.Phase != "released" {
			if j.Phase == "prepared" && j.Change.Deadline.Before(time.Now()) {
				j.Phase = "reverted"
				if e = writeJSON(r.file("changes", j.Change.ID+".json"), j); e != nil {
					return e
				}
				continue
			}
			return errors.New("instance_has_pending_change")
		}
	}
	entries, _ = os.ReadDir(r.file("certificate-transactions"))
	for _, entry := range entries {
		j, e := r.certTransaction(strings.TrimSuffix(entry.Name(), ".json"))
		if e != nil || j.ID == except || j.Phase == "confirmed" || j.Phase == "reverted" || j.Phase == "released" {
			continue
		}
		if j.Phase == "prepared" && j.Deadline.Before(time.Now()) {
			j.Phase = "reverted"
			writeJSON(r.file("certificate-transactions", j.ID+".json"), j)
			continue
		}
		for _, member := range j.Members {
			if member.Instance.ID == instance {
				return errors.New("instance_has_pending_certificate_change")
			}
		}
	}
	return nil
}
func ownedListener(ctx context.Context, unit string, bind engine.Binding) bool {
	b, e := run(ctx, "systemctl", "show", unit, "--property=MainPID", "--value")
	if e != nil {
		return false
	}
	pid := strings.TrimSpace(string(b))
	if pid == "" || pid == "0" {
		return false
	}
	flag := "-Hlnpt"
	if bind.Protocol == "udp" {
		flag = "-Hlnpu"
	}
	b, e = run(ctx, "ss", flag)
	if e != nil {
		return false
	}
	found := false
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		ep, e := engine.ParseEndpoint(fields[3])
		if e != nil || !engine.Conflict(bind, engine.Binding{Host: ep.Host, Port: ep.Port, Protocol: bind.Protocol}) {
			continue
		}
		if !strings.Contains(line, "pid="+pid+",") {
			return false
		}
		found = true
	}
	return found
}
