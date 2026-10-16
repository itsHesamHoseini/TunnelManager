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

type Certificate struct {
	RequestID      string   `json:"request_id"`
	ID             string   `json:"id"`
	Domain         string   `json:"domain"`
	Cert           string   `json:"cert"`
	Key            string   `json:"key,omitempty"`
	PKCS12Password string   `json:"pkcs12_password,omitempty"`
	ExpectedHash   string   `json:"expected_hash"`
	Instances      []string `json:"instances"`
	TrustOnly      bool     `json:"trust_only"`
	Confirm        bool     `json:"confirm"`
}

func (r *Runtime) deployCertificate(ctx context.Context, b []byte) (result any, err error) {
	var q Certificate
	if e := decode(b, &q); e != nil {
		return nil, e
	}
	if !q.Confirm || !engine.ID(q.ID) || !engine.ID(q.RequestID) {
		return nil, errors.New("certificate_deployment_confirmation_required")
	}
	dir := filepath.Join(r.ConfigDir, "certificates", q.ID)
	if len(q.Instances) > 50 {
		return nil, errors.New("certificate_impact_limit")
	}
	if len(q.Cert) > 32768 || len(q.Key) > 16384 {
		return nil, errors.New("certificate_size_limit")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(q.Cert)) {
		return nil, errors.New("certificate_parse_failed")
	}
	if !q.TrustOnly {
		pair, e := tls.X509KeyPair([]byte(q.Cert), []byte(q.Key))
		if e != nil {
			return nil, errors.New("certificate_key_mismatch")
		}
		leaf, e := x509.ParseCertificate(pair.Certificate[0])
		if e != nil || leaf.VerifyHostname(q.Domain) != nil || time.Until(leaf.NotAfter) < time.Hour {
			return nil, errors.New("certificate_name_or_expiry_invalid")
		}
	}
	if q.TrustOnly {
		block, _ := pem.Decode([]byte(q.Cert))
		if block == nil {
			return nil, errors.New("certificate_parse_failed")
		}
		leaf, e := x509.ParseCertificate(block.Bytes)
		if e != nil || leaf.VerifyHostname(q.Domain) != nil || time.Until(leaf.NotAfter) < time.Hour {
			return nil, errors.New("certificate_name_or_expiry_invalid")
		}
	}
	oldCert, _ := os.ReadFile(filepath.Join(dir, "cert.pem"))
	if len(oldCert) > 0 && q.ExpectedHash != engine.Digest(oldCert) {
		return nil, errors.New("certificate_drift")
	}
	if len(oldCert) == 0 && q.ExpectedHash != "" {
		return nil, errors.New("certificate_drift")
	}
	j := certificateJournal{ID: "cert_" + q.RequestID, Dir: dir, Old: map[string][]byte{}, Phase: "prepared"}
	for _, id := range q.Instances {
		if e := r.pending(id, ""); e != nil {
			return nil, e
		}
		if v, _, e := registryRaw(r, id); e != nil {
			return nil, e
		} else {
			if !v.Stopped && !v.Disabled && isState(ctx, "is-active", v.Unit, "active") {
				j.Restart = append(j.Restart, v.Unit)
			}
		}
	}
	backup := r.file("certificate-backups", q.ID, time.Now().UTC().Format("20060102T150405.000000000"))
	if len(oldCert) > 0 {
		if e := os.MkdirAll(backup, 0700); e != nil {
			return nil, e
		}
		for _, name := range []string{"cert.pem", "key.pem", "identity.pfx"} {
			if v, e := os.ReadFile(filepath.Join(dir, name)); e == nil {
				config.Atomic(filepath.Join(backup, name), v, 0600)
			}
		}
	}
	for _, name := range []string{"cert.pem", "key.pem", "identity.pfx"} {
		old, e := os.ReadFile(filepath.Join(dir, name))
		if e == nil {
			j.Old[name] = old
		}
	}
	if err = writeJSON(r.file("certificate-changes", j.ID+".json"), j); err != nil {
		return nil, err
	}
	if err = r.armRollback(ctx, Journal{Change: Change{ID: j.ID, Deadline: time.Now().Add(90 * time.Second)}}); err != nil {
		return nil, err
	}
	j.Phase = "applying"
	if err = writeJSON(r.file("certificate-changes", j.ID+".json"), j); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if e := r.restoreCertificate(context.WithoutCancel(ctx), j.ID); e != nil {
				err = errors.New("certificate_restore_failed_local_timer_retained")
			}
		}
	}()
	if e := config.Atomic(filepath.Join(dir, "cert.pem"), []byte(q.Cert), 0600); e != nil {
		return nil, e
	}
	if !q.TrustOnly {
		if e := config.Atomic(filepath.Join(dir, "key.pem"), []byte(q.Key), 0600); e != nil {
			return nil, e
		}
		if q.PKCS12Password != "" {
			if strings.ContainsAny(q.PKCS12Password, "\r\n") {
				return nil, errors.New("invalid_pkcs12_password")
			}
			cmd := exec.CommandContext(ctx, "openssl", "pkcs12", "-export", "-out", filepath.Join(dir, "identity.pfx"), "-inkey", filepath.Join(dir, "key.pem"), "-in", filepath.Join(dir, "cert.pem"), "-passout", "stdin")
			cmd.Stdin = strings.NewReader(q.PKCS12Password + "\n")
			if e := cmd.Run(); e != nil {
				return nil, errors.New("pkcs12_generation_failed")
			}
			os.Chmod(filepath.Join(dir, "identity.pfx"), 0600)
		}
	}
	if q.TrustOnly {
		os.Remove(filepath.Join(dir, "key.pem"))
		os.Remove(filepath.Join(dir, "identity.pfx"))
	}
	for _, id := range q.Instances {
		v, _ := r.load(id)
		if v.Stopped || v.Disabled {
			continue
		}
		if _, e := run(ctx, "systemctl", "reload-or-restart", "--", v.Unit); e != nil {
			return nil, errors.New("dependent_unit_reload_failed_backup_retained")
		}
	}
	j.Phase = "confirmed"
	if err = writeJSON(r.file("certificate-changes", j.ID+".json"), j); err != nil {
		return nil, err
	}
	r.clearTimer(ctx, j.ID)
	return map[string]any{"deployed": true, "hash": engine.Digest([]byte(q.Cert)), "instances": q.Instances, "private_key_deployed": !q.TrustOnly}, nil
}

type certificateJournal struct {
	ID, Dir, Phase string
	Old            map[string][]byte
	Restart        []string
}

func (r *Runtime) restoreCertificate(ctx context.Context, id string) error {
	if !engine.ID(id) {
		return errors.New("invalid_certificate_change_id")
	}
	b, e := os.ReadFile(r.file("certificate-changes", id+".json"))
	var j certificateJournal
	if e != nil || json.Unmarshal(b, &j) != nil {
		return errors.New("certificate_journal_missing")
	}
	if j.Phase == "confirmed" || j.Phase == "reverted" {
		return nil
	}
	if !strings.HasPrefix(j.Dir, filepath.Join(r.ConfigDir, "certificates")+string(os.PathSeparator)) {
		return errors.New("certificate_journal_path_invalid")
	}
	for _, name := range []string{"cert.pem", "key.pem", "identity.pfx"} {
		path := filepath.Join(j.Dir, name)
		if old, ok := j.Old[name]; ok {
			if e = config.Atomic(path, old, 0600); e != nil {
				return e
			}
		} else {
			if e = os.Remove(path); e != nil && !os.IsNotExist(e) {
				return e
			}
		}
	}
	for _, unit := range j.Restart {
		if !unitRE.MatchString(unit) {
			return errors.New("invalid_backup_unit")
		}
		if _, e = run(ctx, "systemctl", "restart", "--", unit); e != nil {
			return e
		}
	}
	j.Phase = "reverted"
	if e = writeJSON(r.file("certificate-changes", id+".json"), j); e != nil {
		return e
	}
	r.clearTimer(ctx, id)
	return nil
}
