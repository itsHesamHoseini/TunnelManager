package nodeops

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/itsHesamHoseini/TunnelManager/internal/config"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
)

type certMember struct {
	Instance Instance
	Active   bool
}
type certState struct{ ID, Hash string }
type certTransaction struct {
	ID, Certificate, RequestHash, Phase, NewHash string
	Deadline                                     time.Time
	Old, New                                     map[string][]byte
	Previous                                     *certState
	Members                                      []certMember
}

var certFiles = []string{"cert.pem", "key.pem", "identity.pfx"}

func filesHash(files map[string][]byte) string {
	if len(files) == 0 {
		return ""
	}
	b, _ := json.Marshal(files)
	return engine.Digest(b)
}
func (r *Runtime) certFiles(id string) (map[string][]byte, error) {
	if !engine.ID(id) {
		return nil, errors.New("invalid_certificate_id")
	}
	out := map[string][]byte{}
	for _, name := range certFiles {
		p := filepath.Join(r.ConfigDir, "certificates", id, name)
		b, e := readRegular(p, 131072)
		if e != nil {
			if _, e := os.Lstat(p); os.IsNotExist(e) {
				continue
			}
			return nil, errors.New("certificate_file_unreadable")
		}
		out[name] = b
	}
	return out, nil
}
func (r *Runtime) certTransaction(id string) (certTransaction, error) {
	var j certTransaction
	if !engine.ID(id) {
		return j, errors.New("invalid_certificate_transaction")
	}
	b, e := os.ReadFile(r.file("certificate-transactions", id+".json"))
	if e != nil || json.Unmarshal(b, &j) != nil || j.ID != id || !engine.ID(j.Certificate) {
		return j, errors.New("certificate_journal_missing")
	}
	return j, nil
}
func (r *Runtime) certState(id string) *certState {
	var s certState
	b, e := os.ReadFile(r.file("certificate-state", id+".json"))
	if e != nil || json.Unmarshal(b, &s) != nil {
		return nil
	}
	return &s
}
func certLeaf(q Certificate) (*x509.Certificate, error) {
	if len(q.Cert) > 32768 || len(q.Key) > 16384 {
		return nil, errors.New("certificate_size_limit")
	}
	block, _ := pem.Decode([]byte(q.Cert))
	if block == nil {
		return nil, errors.New("certificate_parse_failed")
	}
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil || leaf.VerifyHostname(q.Domain) != nil || leaf.NotBefore.After(time.Now().Add(time.Minute)) || time.Until(leaf.NotAfter) < time.Hour {
		return nil, errors.New("certificate_name_or_expiry_invalid")
	}
	if !q.TrustOnly {
		if _, e = tls.X509KeyPair([]byte(q.Cert), []byte(q.Key)); e != nil {
			return nil, errors.New("certificate_key_mismatch")
		}
	}
	return leaf, nil
}
func (r *Runtime) certificateMembers(ctx context.Context, q Certificate, leaf *x509.Certificate) ([]certMember, error) {
	if len(q.Instances) > 50 {
		return nil, errors.New("certificate_impact_limit")
	}
	selected := map[string]bool{}
	for _, id := range q.Instances {
		if !engine.ID(id) || selected[id] {
			return nil, errors.New("invalid_certificate_instance_selection")
		}
		selected[id] = true
	}
	entries, _ := os.ReadDir(r.file("instances"))
	out := []certMember{}
	dir := filepath.ToSlash(filepath.Join(r.ConfigDir, "certificates", q.ID)) + "/"
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		v, e := r.load(id)
		if e != nil {
			continue
		}
		raw, e := readRegular(v.Path, 65536)
		if e != nil {
			continue
		}
		data, e := engine.Parse(string(raw))
		if e != nil {
			continue
		}
		uses := false
		var walk func(map[string]any)
		walk = func(m map[string]any) {
			for _, value := range m {
				if child, ok := value.(map[string]any); ok {
					walk(child)
				} else if s, ok := value.(string); ok {
					for _, name := range certFiles {
						if s == dir+name {
							uses = true
						}
					}
				}
			}
		}
		walk(data)
		if !uses {
			continue
		}
		if !selected[id] {
			return nil, errors.New("include_all_instances_using_this_certificate")
		}
		if _, _, e = registryRaw(r, id); e != nil {
			return nil, e
		}
		if e = r.pending(id, "cert_"+q.RequestID); e != nil {
			return nil, e
		}
		if q.TrustOnly && v.Role == "server" {
			return nil, errors.New("listener_still_requires_private_certificate_identity")
		}
		if v.Engine == "rathole" && v.Role == "client" {
			side, _ := data["client"].(map[string]any)
			transport, _ := side["transport"].(map[string]any)
			tlsConfig, _ := transport["tls"].(map[string]any)
			hostname, _ := tlsConfig["hostname"].(string)
			if hostname == "" {
				remote, _ := side["remote_addr"].(string)
				ep, e := engine.ParseEndpoint(remote)
				if e == nil {
					hostname = ep.Host
				}
			}
			if hostname != "" && leaf.VerifyHostname(hostname) != nil {
				return nil, errors.New("certificate_does_not_match_linked_peer_hostname")
			}
		}
		out = append(out, certMember{Instance: v, Active: isState(ctx, "is-active", v.Unit, "active")})
		delete(selected, id)
	}
	if len(selected) > 0 {
		return nil, errors.New("selected_instance_does_not_use_this_certificate")
	}
	return out, nil
}
func (r *Runtime) prepareCert(ctx context.Context, q Certificate) (any, error) {
	leaf, e := certLeaf(q)
	if e != nil {
		return nil, e
	}
	id := "cert_" + q.RequestID
	fingerprint := q
	fingerprint.Stage = ""
	fingerprint.Deadline = time.Time{}
	b, _ := json.Marshal(fingerprint)
	hash := engine.Digest(b)
	if j, e := r.certTransaction(id); e == nil {
		if j.RequestHash != hash {
			return nil, errors.New("certificate_request_identity_conflict")
		}
		if j.Phase == "reverted" {
			return nil, errors.New("certificate_change_already_reverted")
		}
		return map[string]any{"prepared": true, "hash": j.NewHash}, nil
	}
	if e := r.pendingCertificate(q.ID, id); e != nil {
		return nil, e
	}
	old, e := r.certFiles(q.ID)
	if e != nil {
		return nil, e
	}
	if filesHash(old) != q.ExpectedHash {
		return nil, errors.New("certificate_drift")
	}
	members, e := r.certificateMembers(ctx, q, leaf)
	if e != nil {
		return nil, e
	}
	next := map[string][]byte{"cert.pem": []byte(q.Cert)}
	if !q.TrustOnly {
		next["key.pem"] = []byte(q.Key)
		if q.PKCS12Password != "" {
			if strings.ContainsAny(q.PKCS12Password, "\r\n") {
				return nil, errors.New("invalid_pkcs12_password")
			}
			dir := r.file("certificate-staging", q.RequestID)
			for _, name := range []string{"cert.pem", "key.pem"} {
				if e = config.Atomic(filepath.Join(dir, name), next[name], 0600); e != nil {
					return nil, e
				}
			}
			cmd := exec.CommandContext(ctx, "openssl", "pkcs12", "-export", "-out", filepath.Join(dir, "identity.pfx"), "-inkey", filepath.Join(dir, "key.pem"), "-in", filepath.Join(dir, "cert.pem"), "-passout", "stdin")
			cmd.Stdin = strings.NewReader(q.PKCS12Password + "\n")
			e = cmd.Run()
			if e == nil {
				next["identity.pfx"], e = readRegular(filepath.Join(dir, "identity.pfx"), 131072)
			}
			for _, name := range certFiles {
				os.Remove(filepath.Join(dir, name))
			}
			os.Remove(dir)
			if e != nil {
				return nil, errors.New("pkcs12_generation_failed")
			}
		}
	}
	j := certTransaction{ID: id, Certificate: q.ID, RequestHash: hash, Phase: "prepared", Old: old, New: next, NewHash: filesHash(next), Previous: r.certState(q.ID), Members: members}
	j.Deadline = time.Now().Add(5 * time.Minute)
	if e = writeJSON(r.file("certificate-transactions", id+".json"), j); e != nil {
		return nil, e
	}
	return map[string]any{"prepared": true, "hash": j.NewHash, "instances": q.Instances, "scope": "files and all registered consumers; no changes applied"}, nil
}
func (r *Runtime) writeCertFiles(id string, files map[string][]byte) error {
	dir := filepath.Join(r.ConfigDir, "certificates", id)
	for _, name := range certFiles {
		p := filepath.Join(dir, name)
		if b, ok := files[name]; ok {
			if e := config.Atomic(p, b, 0600); e != nil {
				return e
			}
		} else {
			if e := os.Remove(p); e != nil && !os.IsNotExist(e) {
				return e
			}
		}
	}
	return nil
}
func (r *Runtime) verifyCertState(ctx context.Context, j certTransaction) error {
	files, e := r.certFiles(j.Certificate)
	state := r.certState(j.Certificate)
	if e != nil || filesHash(files) != j.NewHash || state == nil || state.ID != j.ID {
		return errors.New("certificate_drift_or_newer_deployment")
	}
	for _, m := range j.Members {
		v, _, e := registryRaw(r, m.Instance.ID)
		if e != nil {
			return e
		}
		if v.Epoch != m.Instance.Epoch {
			return errors.New("newer_service_intent_blocks_certificate_rollback")
		}
	}
	return nil
}
func (r *Runtime) deployCertificate(ctx context.Context, b []byte) (any, error) {
	var q Certificate
	if e := decode(b, &q); e != nil {
		return nil, e
	}
	if !q.Confirm || !engine.ID(q.ID) || !engine.ID(q.RequestID) || len(q.RequestID) > 59 {
		return nil, errors.New("certificate_deployment_confirmation_required")
	}
	if q.Stage == "prepare" {
		return r.prepareCert(ctx, q)
	}
	j, e := r.certTransaction("cert_" + q.RequestID)
	if e != nil {
		return nil, e
	}
	if j.Certificate != q.ID {
		return nil, errors.New("certificate_transaction_mismatch")
	}
	switch q.Stage {
	case "activate":
		if j.Phase == "applying" {
			if e = r.restoreCertificate(ctx, j.ID); e != nil {
				return nil, e
			}
			return nil, errors.New("interrupted_certificate_activation_reverted")
		}
		if j.Phase == "confirmed" || j.Phase == "awaiting_confirmation" {
			if e = r.verifyCertState(ctx, j); e != nil {
				return nil, e
			}
			return map[string]any{"activated": true, "hash": j.NewHash}, nil
		}
		if j.Phase != "prepared" {
			return nil, errors.New("certificate_change_not_prepared")
		}
		if j.Deadline.Before(time.Now()) {
			return nil, errors.New("certificate_preparation_expired")
		}
		if time.Until(q.Deadline) < 15*time.Second || time.Until(q.Deadline) > 95*time.Second {
			return nil, errors.New("invalid_certificate_deadline")
		}
		current, e := r.certFiles(q.ID)
		if e != nil || filesHash(current) != filesHash(j.Old) {
			return nil, errors.New("certificate_drift")
		}
		for _, m := range j.Members {
			v, _, e := registryRaw(r, m.Instance.ID)
			if e != nil {
				return nil, e
			}
			if v.Epoch != m.Instance.Epoch {
				return nil, errors.New("service_changed_since_certificate_preview")
			}
		}
		j.Deadline = q.Deadline
		if e = r.armRollback(ctx, Journal{Change: Change{ID: j.ID, Deadline: j.Deadline}}); e != nil {
			return nil, e
		}
		j.Phase = "applying"
		if e = writeJSON(r.file("certificate-transactions", j.ID+".json"), j); e != nil {
			return nil, e
		}
		if e = r.writeCertFiles(q.ID, j.New); e != nil {
			return nil, e
		}
		if e = writeJSON(r.file("certificate-state", q.ID+".json"), certState{ID: j.ID, Hash: j.NewHash}); e != nil {
			return nil, e
		}
		for _, m := range j.Members {
			if m.Instance.Stopped {
				continue
			}
			if _, e = run(ctx, "systemctl", "reload-or-restart", "--", m.Instance.Unit); e != nil {
				return nil, errors.New("dependent_unit_reload_failed_local_rollback_armed")
			}
			if !isState(ctx, "is-active", m.Instance.Unit, "active") {
				return nil, errors.New("dependent_unit_not_active_local_rollback_armed")
			}
		}
		j.Phase = "awaiting_confirmation"
		if e = writeJSON(r.file("certificate-transactions", j.ID+".json"), j); e != nil {
			return nil, e
		}
		return map[string]any{"activated": true, "hash": j.NewHash, "deadline": j.Deadline}, nil
	case "confirm":
		if j.Phase != "awaiting_confirmation" && j.Phase != "confirmed" {
			return nil, errors.New("certificate_change_not_activated")
		}
		if j.Phase != "confirmed" && !j.Deadline.After(time.Now()) {
			return nil, errors.New("certificate_confirmation_expired")
		}
		if e = r.verifyCertState(ctx, j); e != nil {
			return nil, e
		}
		for _, m := range j.Members {
			if !m.Instance.Stopped && !isState(ctx, "is-active", m.Instance.Unit, "active") {
				return nil, errors.New("dependent_unit_not_active")
			}
		}
		j.Phase = "confirmed"
		if e = writeJSON(r.file("certificate-transactions", j.ID+".json"), j); e != nil {
			return nil, e
		}
		r.clearTimer(ctx, j.ID)
		return map[string]any{"confirmed": true, "hash": j.NewHash}, nil
	case "rollback":
		return nil, r.revertCert(ctx, j.ID, true)
	default:
		return nil, errors.New("unknown_certificate_stage")
	}
}
func (r *Runtime) pendingCertificate(id, except string) error {
	entries, _ := os.ReadDir(r.file("certificate-transactions"))
	for _, entry := range entries {
		j, e := r.certTransaction(strings.TrimSuffix(entry.Name(), ".json"))
		if e != nil || j.ID == except || j.Certificate != id || j.Phase == "confirmed" || j.Phase == "reverted" {
			continue
		}
		if j.Phase == "prepared" && j.Deadline.Before(time.Now()) {
			j.Phase = "reverted"
			if e = writeJSON(r.file("certificate-transactions", j.ID+".json"), j); e != nil {
				return e
			}
			continue
		}
		return errors.New("certificate_has_pending_change")
	}
	return nil
}
func (r *Runtime) restoreCertificate(ctx context.Context, id string) error {
	return r.revertCert(ctx, id, false)
}
func (r *Runtime) revertCert(parent context.Context, id string, compensate bool) error {
	ctx, done := context.WithTimeout(parent, 2*time.Minute)
	defer done()
	j, e := r.certTransaction(id)
	if e != nil {
		return e
	}
	if j.Phase == "reverted" || j.Phase == "confirmed" && !compensate {
		return nil
	}
	if j.Phase == "confirmed" {
		if e = r.verifyCertState(ctx, j); e != nil {
			return e
		}
	}
	if j.Phase != "prepared" {
		// A partially written activation may contain old or new files only. Refuse
		// to overwrite an unrelated manual edit or a later deployment.
		current, err := r.certFiles(j.Certificate)
		if err != nil {
			return err
		}
		state := r.certState(j.Certificate)
		if state != nil && state.ID != j.ID && (j.Previous == nil || state.ID != j.Previous.ID) {
			return errors.New("certificate_drift_or_newer_deployment")
		}
		for _, name := range certFiles {
			value := string(current[name])
			if value != string(j.Old[name]) && value != string(j.New[name]) {
				return errors.New("certificate_drift_or_newer_deployment")
			}
		}
		if e = r.writeCertFiles(j.Certificate, j.Old); e != nil {
			return e
		}
		if j.Previous == nil {
			os.Remove(r.file("certificate-state", j.Certificate+".json"))
		} else {
			if e = writeJSON(r.file("certificate-state", j.Certificate+".json"), j.Previous); e != nil {
				return e
			}
		}
		for _, m := range j.Members {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			v, e := r.load(m.Instance.ID)
			if e != nil {
				return e
			}
			if v.Stopped {
				continue
			}
			action := "stop"
			if m.Active {
				action = "restart"
			}
			if _, e = run(ctx, "systemctl", action, "--", v.Unit); e != nil {
				return e
			}
		}
	}
	j.Phase = "reverted"
	if e = writeJSON(r.file("certificate-transactions", id+".json"), j); e != nil {
		return e
	}
	r.clearTimer(ctx, id)
	return nil
}
