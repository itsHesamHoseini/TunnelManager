package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/itsHesamHoseini/TunnelManager/internal/nodeops"
	"time"
)

func (s *Server) deployCertificateTransaction(ctx context.Context, id string, q JobPayload) {
	req, revision, e := s.readCertificate(ctx, q.Certificate)
	if e != nil || revision != q.ExpectedRevision {
		s.phase(ctx, id, "failed", nil, errors.New("certificate_revision_changed"))
		return
	}
	var targets []CertificateDeployment
	if json.Unmarshal(q.Payload, &targets) != nil || len(targets) == 0 {
		s.phase(ctx, id, "failed", nil, errors.New("invalid_certificate_targets"))
		return
	}
	command := func(target CertificateDeployment, stage string, payload nodeops.Certificate) (map[string]any, error) {
		s.step(ctx, id, "certificate."+stage, target.Node, "running", "")
		v, e := s.command(ctx, id, target.Node, "certificate_"+stage, "certificate.deploy", payload)
		var out map[string]any
		json.Unmarshal(v.Data, &out)
		status, code := "succeeded", ""
		if e != nil {
			status = "failed"
			code = e.Error()
		}
		s.step(ctx, id, "certificate."+stage, target.Node, status, code)
		return out, e
	}
	fail := func(cause error) {
		q.RecoveryAttempt++
		if q.FailureCode == "" {
			q.FailureCode = cause.Error()
		}
		pending, review := false, false
		recovery := []any{}
		for _, target := range targets {
			payload := nodeops.Certificate{ID: q.Certificate, RequestID: id, Stage: "rollback", Confirm: true}
			_, e := s.command(ctx, id, target.Node, fmt.Sprintf("certificate_rollback_%d", q.RecoveryAttempt), "certificate.deploy", payload)
			restored := e == nil
			code := ""
			if e != nil {
				code = e.Error()
				if code == "certificate_journal_missing" {
					var activated bool
					s.DB.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM commands WHERE operation_id=$1 AND node_id=$2 AND stage='certificate_activate')", id, target.Node).Scan(&activated)
					restored = !activated
					if activated {
						review = true
					}
				} else if code == "certificate_drift_or_newer_deployment" || code == "newer_service_intent_blocks_certificate_rollback" || code == "manual_config_drift" || code == "manual_unit_drift" {
					review = true
				} else {
					pending = true
				}
			}
			recovery = append(recovery, map[string]any{"node": target.Node, "restored": restored, "code": code})
		}
		phase := "failed"
		if pending {
			phase = "recovery_pending"
		}
		if review || q.RecoveryAttempt >= 1000 {
			phase = "needs_review"
		}
		cipher, e := s.sealValue("operation:"+id, q)
		if e == nil {
			s.DB.Exec(ctx, "UPDATE operations SET cipher=$1 WHERE id=$2", cipher, id)
		}
		s.phase(ctx, id, phase, map[string]any{"recovery": recovery, "scope": "only selected certificate files and all registered consumers; local timers survive disconnection"}, errors.New(q.FailureCode))
	}
	if q.FailureCode != "" {
		fail(errors.New(q.FailureCode))
		return
	}
	for _, target := range targets {
		var expected string
		s.DB.QueryRow(ctx, "SELECT hash FROM certificate_links WHERE certificate_id=$1 AND node_id=$2 LIMIT 1", q.Certificate, target.Node).Scan(&expected)
		payload := nodeops.Certificate{ID: q.Certificate, RequestID: id, Stage: "prepare", Domain: req.Domain, Cert: req.Cert, Key: req.Key, PKCS12Password: req.PKCS12Password, ExpectedHash: expected, Instances: target.Instances, TrustOnly: target.TrustOnly, Confirm: true}
		if target.TrustOnly {
			payload.Key = ""
			payload.PKCS12Password = ""
		}
		if _, e := command(target, "prepare", payload); e != nil {
			fail(e)
			return
		}
	}
	if q.Deadline.IsZero() {
		q.Deadline = time.Now().Add(90 * time.Second)
		cipher, e := s.sealValue("operation:"+id, q)
		if e != nil {
			fail(e)
			return
		}
		if _, e = s.DB.Exec(ctx, "UPDATE operations SET cipher=$1,deadline=$2 WHERE id=$3", cipher, q.Deadline, id); e != nil {
			fail(e)
			return
		}
	}
	hashes := map[string]string{}
	for _, target := range targets {
		out, e := command(target, "activate", nodeops.Certificate{ID: q.Certificate, RequestID: id, Stage: "activate", Deadline: q.Deadline, Confirm: true})
		if e != nil {
			fail(e)
			return
		}
		hashes[target.Node], _ = out["hash"].(string)
	}
	if !q.Deadline.After(time.Now()) {
		fail(errors.New("certificate_confirmation_expired"))
		return
	}
	for _, target := range targets {
		if _, e := command(target, "confirm", nodeops.Certificate{ID: q.Certificate, RequestID: id, Stage: "confirm", Confirm: true}); e != nil {
			fail(e)
			return
		}
	}
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		fail(e)
		return
	}
	defer tx.Rollback(ctx)
	for _, target := range targets {
		instances := target.Instances
		if len(instances) == 0 {
			instances = []string{""}
		}
		for _, instance := range instances {
			_, e = tx.Exec(ctx, "INSERT INTO certificate_links(certificate_id,node_id,instance_id,trust_only,hash,revision)VALUES($1,$2,$3,$4,$5,$6)ON CONFLICT(certificate_id,node_id,instance_id)DO UPDATE SET hash=EXCLUDED.hash,trust_only=EXCLUDED.trust_only,revision=EXCLUDED.revision", q.Certificate, target.Node, instance, target.TrustOnly, hashes[target.Node], revision)
			if e != nil {
				fail(e)
				return
			}
		}
		_, e = tx.Exec(ctx, "UPDATE certificate_links SET hash=$1,revision=$2 WHERE certificate_id=$3 AND node_id=$4", hashes[target.Node], revision, q.Certificate, target.Node)
		if e != nil {
			fail(e)
			return
		}
	}
	result, _ := json.Marshal(map[string]any{"certificate_id": q.Certificate, "deployments": targets, "revision": revision})
	if _, e = tx.Exec(ctx, "UPDATE operations SET phase='succeeded',result=$1,updated=now() WHERE id=$2", result, id); e != nil {
		fail(e)
		return
	}
	if e = tx.Commit(ctx); e != nil {
		return
	}
	s.Audit(ctx, "certificate-deployment", req.Name, "all-selected-nodes-confirmed")
}

func (s *Server) queueCertificateDeployment(ctx context.Context, id string, revision int64, name string) {
	rows, e := s.DB.Query(ctx, "SELECT node_id,instance_id,trust_only FROM certificate_links WHERE certificate_id=$1 ORDER BY node_id,instance_id", id)
	if e != nil {
		return
	}
	group := map[string]*CertificateDeployment{}
	for rows.Next() {
		var node, instance string
		var trust bool
		rows.Scan(&node, &instance, &trust)
		if group[node] == nil {
			group[node] = &CertificateDeployment{Node: node, TrustOnly: true}
		}
		if instance != "" {
			group[node].Instances = append(group[node].Instances, instance)
		}
		if !trust {
			group[node].TrustOnly = false
		}
	}
	rows.Close()
	targets := []CertificateDeployment{}
	for _, target := range group {
		targets = append(targets, *target)
	}
	if len(targets) == 0 {
		return
	}
	payload, _ := json.Marshal(targets)
	s.newJob(ctx, fmt.Sprintf("auto_deploy_%s_%d_%d", id, revision, time.Now().Unix()/300), "certificate", id, name, JobPayload{Kind: "deploy", Certificate: id, ExpectedRevision: revision, Payload: payload})
}
func (s *Server) scheduleCertificateDeployments(ctx context.Context) {
	rows, e := s.DB.Query(ctx, `SELECT id,name,revision FROM certificates c WHERE metadata->>'auto_deploy'='true' AND EXISTS(SELECT 1 FROM certificate_links l WHERE l.certificate_id=c.id AND l.revision<c.revision)AND NOT EXISTS(SELECT 1 FROM operations o WHERE o.target=c.id AND o.kind='certificate' AND(o.phase IN('queued','running','recovery_pending') OR o.created>now()-interval '5 minutes')) LIMIT 2`)
	if e != nil {
		return
	}
	type item struct {
		id, name string
		rev      int64
	}
	items := []item{}
	for rows.Next() {
		var v item
		rows.Scan(&v.id, &v.name, &v.rev)
		items = append(items, v)
	}
	rows.Close()
	for _, v := range items {
		s.queueCertificateDeployment(ctx, v.id, v.rev, v.name)
	}
}
