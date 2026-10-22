package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"github.com/itsHesamHoseini/TunnelManager/internal/nodeops"
	"github.com/itsHesamHoseini/TunnelManager/internal/protocol"
	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
)

type TunnelRecord struct {
	Spec      engine.Spec       `json:"spec"`
	Instances map[string]string `json:"instances"`
	Hashes    map[string]string `json:"hashes"`
}

func (s *Server) readTunnel(ctx context.Context, id string) (TunnelRecord, int64, bool, error) {
	var cipher []byte
	var revision int64
	var managed bool
	e := s.DB.QueryRow(ctx, "SELECT cipher,revision,managed FROM tunnels WHERE id=$1", id).Scan(&cipher, &revision, &managed)
	if e != nil {
		return TunnelRecord{}, 0, false, errors.New("tunnel_missing")
	}
	var r TunnelRecord
	e = s.openValue("tunnel:"+id, cipher, &r)
	return r, revision, managed, e
}
func (s *Server) tunnelList(w http.ResponseWriter, r *http.Request) {
	rows, e := s.DB.Query(r.Context(), "SELECT id,name,revision,cipher,managed,desired,health,updated FROM tunnels ORDER BY name")
	if e != nil {
		badOperation(w, e)
		return
	}
	items := []map[string]any{}
	records := []TunnelRecord{}
	for rows.Next() {
		var id, name, desired string
		var rev int64
		var cipher, health []byte
		var managed bool
		var updated time.Time
		if rows.Scan(&id, &name, &rev, &cipher, &managed, &desired, &health, &updated) != nil {
			continue
		}
		var record TunnelRecord
		if s.openValue("tunnel:"+id, cipher, &record) != nil {
			continue
		}
		items = append(items, map[string]any{"id": id, "name": name, "revision": rev, "spec": engine.Public(record.Spec), "instances": record.Instances, "hashes": record.Hashes, "managed": managed, "desired": desired, "health": json.RawMessage(health), "updated": updated})
		records = append(records, record)
	}
	rows.Close()
	for i, rec := range records {
		raw, _ := json.Marshal(items[i]["health"])
		items[i]["health"] = s.currentHealth(r.Context(), raw, rec)
	}
	write(w, items)
}
func (s *Server) tunnelDetail(w http.ResponseWriter, r *http.Request) {
	record, revision, managed, e := s.readTunnel(r.Context(), r.PathValue("id"))
	if e != nil {
		badOperation(w, e)
		return
	}
	var name, desired string
	var health []byte
	s.DB.QueryRow(r.Context(), "SELECT name,desired,health FROM tunnels WHERE id=$1", r.PathValue("id")).Scan(&name, &desired, &health)
	configurations := map[string]string{}
	if !managed {
		// Observation records must preview the actual discovered configuration,
		// including versions/options that the managed renderer cannot reproduce.
		if nodes, err := s.discoveries(r.Context()); err == nil {
			for _, n := range nodes {
				for _, d := range n.Instances {
					if record.Instances[n.ID] == d.ID && d.Configuration != "" {
						configurations[d.Role] = engine.Redact(d.Configuration)
					}
				}
			}
		}
	} else {
		for _, role := range []string{"server", "client"} {
			if raw, e := engine.Render(record.Spec, role); e == nil {
				configurations[role] = engine.Redact(raw)
			}
		}
	}
	rows, e := s.DB.Query(r.Context(), "SELECT revision,at FROM tunnel_versions WHERE tunnel_id=$1 ORDER BY revision DESC LIMIT 50", r.PathValue("id"))
	versions := []map[string]any{}
	if e == nil {
		defer rows.Close()
		for rows.Next() {
			var rev int64
			var at time.Time
			rows.Scan(&rev, &at)
			versions = append(versions, map[string]any{"revision": rev, "at": at})
		}
	}
	if rows != nil {
		rows.Close()
	}
	affected := []map[string]any{}
	seen := map[string]bool{}
	for node, instance := range record.Instances {
		for _, t := range s.affected(r.Context(), node, instance) {
			id, _ := t["id"].(string)
			if !seen[id] {
				seen[id] = true
				affected = append(affected, t)
			}
		}
	}
	if managed {
		plan := JobPayload{Tunnel: r.PathValue("id"), Name: name, Spec: record.Spec, Instances: record.Instances, Hashes: record.Hashes, ExpectedRevision: revision, Action: "preview"}
		if s.expand(r.Context(), &plan) == nil {
			affected = publicAffected(plan)
		}
	}

	write(w, map[string]any{"id": r.PathValue("id"), "name": name, "desired": desired, "health": s.currentHealth(r.Context(), health, record), "configurations": configurations, "revision": revision, "managed": managed, "spec": engine.Public(record.Spec), "instances": record.Instances, "hashes": record.Hashes, "versions": versions, "affected_tunnels": affected})
}
func (s *Server) tunnelPlan(w http.ResponseWriter, r *http.Request) {
	var q struct {
		RequestKey, Name, Tunnel string
		ExpectedRevision         int64
		Spec                     engine.Spec
		RevertRevision           int64
	}
	if !decode(w, r, &q) {
		return
	}
	input, _ := json.Marshal(q)
	requestHash := secure.Hash(string(s.Config.Key) + string(input))
	var priorID, priorTarget, priorHash string
	if s.DB.QueryRow(r.Context(), "SELECT id,target,request_hash FROM operations WHERE request_key=$1", q.RequestKey).Scan(&priorID, &priorTarget, &priorHash) == nil {
		if priorHash != requestHash {
			badOperation(w, errors.New("request_key_reused_with_different_input"))
			return
		}
		write(w, map[string]string{"operation_id": priorID, "tunnel_id": priorTarget})
		return
	}
	id := q.Tunnel
	if id == "" {
		id = secure.Token(15)
	}
	instances := map[string]string{}
	hashes := map[string]string{}
	if q.Tunnel != "" {
		old, rev, managed, e := s.readTunnel(r.Context(), q.Tunnel)
		if e != nil || rev != q.ExpectedRevision {
			badOperation(w, errors.New("tunnel_revision_changed"))
			return
		}
		if !managed {
			badOperation(w, errors.New("explicit_adoption_required"))
			return
		}
		engine.MergeSecrets(&q.Spec, old.Spec)
		instances = old.Instances
		hashes = old.Hashes
		if q.RevertRevision > 0 {
			var cipher []byte
			if s.DB.QueryRow(r.Context(), "SELECT cipher FROM tunnel_versions WHERE tunnel_id=$1 AND revision=$2", q.Tunnel, q.RevertRevision).Scan(&cipher) != nil {
				badOperation(w, errors.New("version_missing"))
				return
			}
			var prior TunnelRecord
			if s.openValue("tunnel:"+id, cipher, &prior) != nil {
				badOperation(w, errors.New("version_unreadable"))
				return
			}
			q.Spec = prior.Spec
		}
	}
	if e := engine.NormalizeRaw(&q.Spec); e != nil {
		badOperation(w, e)
		return
	}
	if e := engine.GenerateSecrets(&q.Spec); e != nil {
		badOperation(w, e)
		return
	}
	if e := engine.Validate(q.Spec); e != nil {
		badOperation(w, e)
		return
	}
	if len(q.Name) < 1 || len(q.Name) > 100 {
		badOperation(w, errors.New("tunnel_name_required"))
		return
	}
	if q.Spec.Transport != "tls" && !strings.HasPrefix(q.Spec.Transport, "wss") {
		q.Spec.Certificate = ""
		q.Spec.CertificateHash = ""
		q.Spec.CertificateRevision = 0
		q.Spec.PKCS12Password = ""
		q.Spec.TLSName = ""
	}
	if q.Spec.Certificate != "" {
		cert, certRevision, e := s.readCertificate(r.Context(), q.Spec.Certificate)
		if e != nil {
			badOperation(w, e)
			return
		}
		if _, e = validateCertificate(cert); e != nil {
			badOperation(w, e)
			return
		}
		q.Spec.PKCS12Password = cert.PKCS12Password
		q.Spec.CertificateHash = engine.Digest([]byte(cert.Cert))
		q.Spec.CertificateRevision = certRevision
		if q.Spec.TLSName == "" {
			q.Spec.TLSName = cert.Domain
		}
		leaf, _ := validateCertificate(cert)
		if leaf.VerifyHostname(q.Spec.TLSName) != nil {
			badOperation(w, errors.New("certificate_peer_hostname_mismatch"))
			return
		}
	}
	if instances[q.Spec.Listener] == "" {
		instances[q.Spec.Listener] = id + "_s"
	}
	if instances[q.Spec.Dialer] == "" {
		instances[q.Spec.Dialer] = id + "_c"
	}
	payload := JobPayload{RequestHash: requestHash, Spec: q.Spec, Tunnel: id, Name: q.Name, ExpectedRevision: q.ExpectedRevision, Instances: instances, Hashes: hashes}
	if e := s.expand(r.Context(), &payload); e != nil {
		badOperation(w, e)
		return
	}
	op, e := s.newJob(r.Context(), q.RequestKey, "plan", id, q.Name, payload)
	if e != nil {
		badOperation(w, e)
		return
	}
	write(w, map[string]string{"operation_id": op, "tunnel_id": id})
}
func (s *Server) planTransition(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Action  string
		Confirm bool
	}
	if !decode(w, r, &q) || !q.Confirm {
		badOperation(w, errors.New("impact_confirmation_required"))
		return
	}
	from, to := "ready", "applying"
	if q.Action == "confirm" {
		from, to = "awaiting_confirmation", "confirming"
	} else if q.Action == "rollback" {
		from, to = "awaiting_confirmation", "reverting"
	} else if q.Action == "cancel" {
		from, to = "ready", "cancelled"
	} else if q.Action != "apply" {
		badOperation(w, errors.New("invalid_plan_action"))
		return
	}
	tx, e := s.DB.Begin(r.Context())
	if e != nil {
		badOperation(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	tag, e := tx.Exec(r.Context(), "UPDATE operations SET phase=$1,updated=now() WHERE id=$2 AND kind='plan' AND phase=$3", to, r.PathValue("id"), from)
	if e != nil || tag.RowsAffected() != 1 {
		badOperation(w, errors.New("operation_state_changed"))
		return
	}
	if q.Action == "cancel" {
		if _, e = tx.Exec(r.Context(), "DELETE FROM port_reservations WHERE plan_id=$1", r.PathValue("id")); e != nil {
			badOperation(w, e)
			return
		}
	}
	if e = tx.Commit(r.Context()); e != nil {
		badOperation(w, e)
		return
	}
	s.Audit(r.Context(), "change-"+q.Action, r.PathValue("id"), "explicitly-confirmed")
	write(w, map[string]bool{"accepted": true})
}
func (s *Server) changeParts(q JobPayload) []struct{ Node, Role string } {
	return []struct{ Node, Role string }{{q.Spec.Listener, "server"}, {q.Spec.Dialer, "client"}}
}
func (s *Server) processPlan(ctx context.Context, id, phase string, q JobPayload) {
	parts := q.Parts
	if len(parts) == 0 {
		s.phase(ctx, id, "failed", nil, errors.New("expanded_plan_required"))
		return
	}
	runPart := func(p ChangePart, stage, kind string, payload any) (protocol.Result, error) {
		s.step(ctx, id, stage, p.Node, "running", "")
		v, e := s.command(ctx, id, p.Node, stage+"_"+engine.Digest([]byte(p.Instance))[:12], kind, payload)
		status := "succeeded"
		code := ""
		if e != nil {
			status = "failed"
			code = e.Error()
		}
		s.step(ctx, id, stage, p.Node, status, code)
		return v, e
	}
	fail := func(cause error) {
		if q.FailureCode == "" {
			q.FailureCode = cause.Error()
		}
		q.RecoveryAttempt++
		recovery := []map[string]any{}
		pending, review := false, false
		for _, p := range parts {
			stage := fmt.Sprintf("rollback_%d_%s", q.RecoveryAttempt, engine.Digest([]byte(p.Instance))[:12])
			s.step(ctx, id, "rollback", p.Node, "running", "")
			_, re := s.command(ctx, id, p.Node, stage, "change.rollback", map[string]any{"ID": changeID(id, p.Instance), "Compensate": true})
			restored := re == nil
			code := ""
			if re != nil {
				code = re.Error()
				if code == "change_journal_missing" {
					var activated bool
					s.DB.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM commands WHERE operation_id=$1 AND node_id=$2 AND stage=$3)", id, p.Node, "activate_"+engine.Digest([]byte(p.Instance))[:12]).Scan(&activated)
					restored = !activated
					if activated {
						review = true
					}
				} else if code == "newer_change_blocks_compensation" || code == "manual_config_drift" || code == "manual_unit_drift" {
					review = true
				} else {
					pending = true
				}
			}
			recovery = append(recovery, map[string]any{"node": p.Node, "restored": restored, "code": code})
			s.step(ctx, id, "rollback", p.Node, map[bool]string{true: "succeeded", false: "failed"}[restored], code)
		}
		next := "failed"
		if pending {
			next = "recovery_pending"
		}
		if review {
			next = "needs_review"
		}
		if q.RecoveryAttempt >= 1000 {
			next = "needs_review"
		}
		cipher, e := s.sealValue("operation:"+id, q)
		if e == nil {
			s.DB.Exec(ctx, "UPDATE operations SET cipher=$1 WHERE id=$2", cipher, id)
		}
		if !pending || review {
			s.DB.Exec(ctx, "DELETE FROM port_reservations WHERE plan_id=$1", id)
		}
		s.phase(ctx, id, next, map[string]any{"recovery": recovery, "local_rollback": "unconfirmed nodes keep their independent local timer", "next_action": map[bool]string{true: "review newer intent/drift before explicit reconciliation", false: "automatic rollback retries after node reconnection"}[review]}, errors.New(q.FailureCode))
	}

	switch phase {
	case "recovery_pending":
		fail(errors.New(q.FailureCode))
		return
	case "queued", "running":
		s.phase(ctx, id, "running", nil, nil)
		previews := map[string]any{}
		for _, p := range parts {
			c := nodeops.Change{ID: changeID(id, p.Instance), Instance: p.Instance, Name: q.Name, Role: p.Role, ExpectedHash: p.Hash, Spec: nodeSpec(p)}
			v, e := runPart(p, "preflight", "change.preflight", c)
			if e != nil {
				s.phase(ctx, id, "failed", nil, e)
				return
			}
			var out map[string]any
			json.Unmarshal(v.Data, &out)
			previews[p.Node+":"+p.Instance] = out
			if good, _ := out["valid"].(bool); !good {
				s.phase(ctx, id, "failed", previews, errors.New("preflight_blocked"))
				return
			}
		}
		if e := s.reserve(ctx, id, q); e != nil {
			s.phase(ctx, id, "failed", previews, e)
			return
		}
		s.phase(ctx, id, "ready", map[string]any{"previews": previews, "affected_tunnels": publicAffected(q), "affected_routes": engine.Public(q.Spec).Routes, "reverse_connection": map[string]string{"from": q.Spec.Dialer, "to": q.Spec.Listener}, "notice": "activation restarts the selected shared units; application health is checked separately"}, nil)
	case "applying":
		for _, g := range q.Updates {
			s.DB.Exec(ctx, `UPDATE tunnels SET health='{"transport":{"status":"unknown","code":"change_in_progress"},"application":{"status":"unknown"}}' WHERE id=$1`, g.ID)
		}
		if q.ExpectedRevision > 0 {
			_, revision, _, e := s.readTunnel(ctx, q.Tunnel)
			if e != nil || revision != q.ExpectedRevision {
				fail(errors.New("tunnel_revision_changed"))
				return
			}
		}
		for _, p := range parts {
			c := nodeops.Change{ID: changeID(id, p.Instance), Instance: p.Instance, Name: q.Name, Role: p.Role, ExpectedHash: p.Hash, Spec: nodeSpec(p), Deadline: time.Now().Add(5 * time.Minute)}
			if _, e := runPart(p, "prepare", "change.prepare", c); e != nil {
				fail(e)
				return
			}
		}
		if q.Deadline.IsZero() {
			q.Deadline = time.Now().Add(90 * time.Second)
			b, e := s.sealValue("operation:"+id, q)
			if e != nil {
				fail(e)
				return
			}
			if _, e = s.DB.Exec(ctx, "UPDATE operations SET cipher=$1,deadline=$2 WHERE id=$3", b, q.Deadline, id); e != nil {
				fail(e)
				return
			}
		}
		deadline := q.Deadline
		intentionallyStopped := false
		for _, p := range parts {
			v, e := runPart(p, "activate", "change.activate", map[string]any{"ID": changeID(id, p.Instance), "Deadline": deadline})
			if e != nil {
				fail(e)
				return
			}
			var out struct {
				Instance nodeops.Instance `json:"instance"`
				Active   bool             `json:"process_active"`
			}
			json.Unmarshal(v.Data, &out)
			intentionallyStopped = intentionallyStopped || out.Instance.Stopped
			if !out.Active && !out.Instance.Stopped {
				fail(errors.New("engine_process_not_active"))
				return
			}
			if q.Hashes == nil {
				q.Hashes = map[string]string{}
			}
			if q.Instances[p.Node] == p.Instance {
				q.Hashes[p.Node] = out.Instance.Hash
			}
			for i := range q.Updates {
				if q.Updates[i].Record.Instances[p.Node] == p.Instance {
					q.Updates[i].Record.Hashes[p.Node] = out.Instance.Hash
				}
			}
		}
		cipher, e := s.sealValue("operation:"+id, q)
		if e != nil {
			fail(e)
			return
		}
		s.DB.Exec(ctx, "UPDATE operations SET cipher=$1 WHERE id=$2", cipher, id)
		if intentionallyStopped {
			s.phase(ctx, id, "awaiting_confirmation", map[string]any{"affected_routes": engine.Public(q.Spec).Routes, "affected_tunnels": publicAffected(q), "deadline": deadline, "process": "intentionally_stopped", "transport": "untested", "application": "untested", "configuration_only": true}, nil)
			return
		}
		var result struct {
			Status string `json:"status"`
		}
		seen := map[string]bool{}
		for _, part := range parts {
			if part.Role != "client" {
				continue
			}
			identity := part.Node + ":" + part.Spec.TransportRemote.String()
			if seen[identity] {
				continue
			}
			seen[identity] = true
			check, e := s.command(ctx, id, part.Node, "post_transport_"+engine.Digest([]byte(identity))[:12], "diagnostic", nodeops.Diagnostic{Kind: "tcp", Endpoint: part.Spec.TransportRemote})
			json.Unmarshal(check.Data, &result)
			if e != nil || result.Status != "passed" {
				fail(errors.New("post_apply_transport_failed"))
				return
			}
			if part.Spec.Transport == "tls" || strings.HasPrefix(part.Spec.Transport, "wss") {
				check, e = s.command(ctx, id, part.Node, "post_tls_"+engine.Digest([]byte(identity))[:12], "diagnostic", nodeops.Diagnostic{Kind: "tls", Endpoint: part.Spec.TransportRemote, CA: part.Spec.Certificate, ServerName: part.Spec.TLSName})
				json.Unmarshal(check.Data, &result)
				if e != nil || result.Status != "passed" {
					fail(errors.New("post_apply_tls_failed"))
					return
				}
			}
		}
		for _, update := range q.Updates {
			if p := update.Record.Spec.Application; p != nil {
				check, e := s.command(ctx, id, update.Record.Spec.Listener, "post_application_"+engine.Digest([]byte(update.ID))[:12], "diagnostic", nodeops.Diagnostic{Kind: p.Kind, Endpoint: p.Endpoint, Path: p.Path, Expected: p.Expected})
				json.Unmarshal(check.Data, &result)
				if e != nil || result.Status != "passed" {
					fail(errors.New("post_apply_application_failed"))
					return
				}
			}
		}
		s.phase(ctx, id, "awaiting_confirmation", map[string]any{"affected_routes": engine.Public(q.Spec).Routes, "affected_tunnels": publicAffected(q), "deadline": deadline, "process": "active", "transport": "passed", "application": map[bool]string{true: "passed", false: "unconfigured"}[q.Spec.Application != nil]}, nil)
	case "confirming":
		var deadline *time.Time
		s.DB.QueryRow(ctx, "SELECT deadline FROM operations WHERE id=$1", id).Scan(&deadline)
		if deadline == nil || deadline.Before(time.Now()) {
			fail(errors.New("confirmation_deadline_expired"))
			return
		}
		for _, p := range parts {
			if _, e := runPart(p, "confirm", "change.confirm", map[string]string{"ID": changeID(id, p.Instance)}); e != nil {
				fail(e)
				return
			}
		}
		for _, p := range parts {
			if _, e := runPart(p, "commit", "change.confirm", map[string]any{"ID": changeID(id, p.Instance), "Commit": true}); e != nil {
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
		for _, g := range q.Updates {
			cipher, err := s.sealValue("tunnel:"+g.ID, g.Record)
			e = err
			if e != nil {
				break
			}
			if g.Revision == 0 {
				_, e = tx.Exec(ctx, "INSERT INTO tunnels(id,name,cipher,managed)VALUES($1,$2,$3,true)", g.ID, g.Name, cipher)
			} else {
				tag, err := tx.Exec(ctx, "UPDATE tunnels SET name=$1,cipher=$2,revision=revision+1,updated=now() WHERE id=$3 AND revision=$4", g.Name, cipher, g.ID, g.Revision)
				e = err
				if e == nil && tag.RowsAffected() != 1 {
					e = errors.New("tunnel_revision_changed")
				}
			}
			if e != nil {
				break
			}
			_, e = tx.Exec(ctx, "INSERT INTO tunnel_versions(tunnel_id,revision,cipher)VALUES($1,$2,$3)", g.ID, g.Revision+1, cipher)
			if e != nil {
				break
			}
		}

		if e == nil {
			_, e = tx.Exec(ctx, "DELETE FROM port_reservations WHERE plan_id=$1", id)
		}
		if e == nil {
			for _, p := range q.Parts {
				if p.Spec.Certificate == "" || (p.Spec.Engine == "backhaul" && p.Role == "client") {
					_, e = tx.Exec(ctx, "DELETE FROM certificate_links WHERE node_id=$1 AND instance_id=$2", p.Node, p.Instance)
					if e != nil {
						break
					}
					continue
				}
				_, e = tx.Exec(ctx, "DELETE FROM certificate_links WHERE node_id=$1 AND instance_id=$2 AND certificate_id<>$3", p.Node, p.Instance, p.Spec.Certificate)
				if e != nil {
					break
				}
				_, e = tx.Exec(ctx, "INSERT INTO certificate_links(certificate_id,node_id,instance_id,trust_only,hash,revision)VALUES($1,$2,$3,$4,COALESCE((SELECT hash FROM certificate_links WHERE certificate_id=$1 AND node_id=$2 LIMIT 1),''),$5)ON CONFLICT(certificate_id,node_id,instance_id)DO UPDATE SET trust_only=EXCLUDED.trust_only,revision=EXCLUDED.revision", p.Spec.Certificate, p.Node, p.Instance, p.Role == "client", p.Spec.CertificateRevision)
				if e != nil {
					break
				}
			}
		}
		if e == nil {
			result, _ := json.Marshal(map[string]any{"tunnel_id": q.Tunnel, "revision": q.ExpectedRevision + 1})
			_, e = tx.Exec(ctx, "UPDATE operations SET phase='succeeded',result=$1,updated=now() WHERE id=$2", result, id)
		}
		if e != nil {
			fail(errors.New("confirmation_database_commit_requires_reconciliation"))
			return
		}
		// A lost COMMIT acknowledgement is ambiguous. The next durable pass reads
		// the operation phase; never compensate a transaction that may be committed.
		if tx.Commit(ctx) != nil {
			return
		}
		s.phase(ctx, id, "succeeded", map[string]any{"tunnel_id": q.Tunnel, "revision": q.ExpectedRevision + 1}, nil)
	case "reverting":
		for _, p := range parts {
			if _, e := runPart(p, "rollback", "change.rollback", map[string]string{"ID": changeID(id, p.Instance)}); e != nil {
				s.phase(ctx, id, "failed", nil, e)
				return
			}
		}
		s.DB.Exec(ctx, "DELETE FROM port_reservations WHERE plan_id=$1", id)
		s.phase(ctx, id, "reverted", nil, nil)
	}
}
func (s *Server) reserve(ctx context.Context, id string, q JobPayload) error {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	tx.Exec(ctx, "DELETE FROM port_reservations WHERE expires<now()")
	for _, b := range engine.Bindings(q.Spec, "server") {
		key := fmt.Sprintf("%s:%d:%s", q.Spec.Listener, b.Port, b.Protocol)
		if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext($1))", key); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, "SELECT host FROM port_reservations WHERE node_id=$1 AND port=$2 AND protocol=$3 AND plan_id<>$4", q.Spec.Listener, b.Port, b.Protocol, id)
		if e != nil {
			return e
		}
		conflict := false
		for rows.Next() {
			var host string
			rows.Scan(&host)
			if engine.Conflict(b, engine.Binding{Host: host, Port: b.Port, Protocol: b.Protocol}) {
				conflict = true
			}
		}
		rows.Close()
		if conflict {
			return errors.New("port_reserved_by_another_change")
		}
		if _, e = tx.Exec(ctx, "INSERT INTO port_reservations(plan_id,node_id,host,port,protocol,expires)VALUES($1,$2,$3,$4,$5,now()+interval '10 minutes') ON CONFLICT DO NOTHING", id, q.Spec.Listener, b.Host, b.Port, b.Protocol); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}
func (s *Server) tunnelAction(w http.ResponseWriter, r *http.Request) {
	var q struct {
		RequestKey, Action string
		Confirm            bool
		ExpectedRevision   int64
	}
	if !decode(w, r, &q) {
		return
	}
	record, rev, managed, e := s.readTunnel(r.Context(), r.PathValue("id"))
	if e != nil || !managed || rev != q.ExpectedRevision || !q.Confirm {
		badOperation(w, errors.New("managed_revision_and_confirmation_required"))
		return
	}
	if !strings.Contains("|start|stop|restart|reload|disable|remove|revoke|", "|"+q.Action+"|") {
		badOperation(w, errors.New("invalid_action"))
		return
	}
	plan := JobPayload{Tunnel: r.PathValue("id"), Spec: record.Spec, Instances: record.Instances, Hashes: record.Hashes, Action: q.Action, ExpectedRevision: rev, Confirm: true}
	s.DB.QueryRow(r.Context(), "SELECT name FROM tunnels WHERE id=$1", plan.Tunnel).Scan(&plan.Name)
	if e = s.expand(r.Context(), &plan); e != nil {
		badOperation(w, e)
		return
	}
	id, e := s.newJob(r.Context(), q.RequestKey, "tunnel-action", r.PathValue("id"), q.Action, plan)
	if e != nil {
		badOperation(w, e)
		return
	}
	write(w, map[string]any{"operation_id": id, "affected_tunnels": publicAffected(plan)})
}
func (s *Server) processTunnelAction(ctx context.Context, id string, q JobPayload) {
	s.phase(ctx, id, "running", nil, nil)
	for _, update := range q.Updates {
		_, revision, managed, e := s.readTunnel(ctx, update.ID)
		if e != nil || !managed || revision != update.Revision {
			s.phase(ctx, id, "failed", nil, errors.New("tunnel_revision_changed"))
			return
		}
	}
	parts := q.Parts
	if len(parts) == 0 {
		for _, p := range s.changeParts(q) {
			parts = append(parts, ChangePart{Node: p.Node, Role: p.Role, Instance: q.Instances[p.Node], Hash: q.Hashes[p.Node]})
		}
	}
	for _, p := range parts {
		s.step(ctx, id, q.Action, p.Node, "running", "")
		_, e := s.command(ctx, id, p.Node, "action_"+p.Instance, "instance.action", map[string]any{"ID": p.Instance, "Action": q.Action, "ExpectedHash": p.Hash, "Confirm": true})
		if e != nil {
			s.phase(ctx, id, "failed", map[string]any{"partial": true, "affected_tunnels": publicAffected(q)}, e)
			return
		}
		s.step(ctx, id, q.Action, p.Node, "succeeded", "")
		s.invalidateHealth(ctx, p.Node, p.Instance, "service_action_requires_new_check")
	}
	desired := "running"
	if q.Action == "stop" || q.Action == "disable" {
		desired = q.Action
	}
	if len(q.Updates) == 0 {
		q.Updates = []TunnelUpdate{{ID: q.Tunnel}}
	}
	if q.Action == "remove" || q.Action == "revoke" {
		for _, p := range parts {
			if q.Action == "revoke" {
				s.freezeCertificateLinks(ctx, p.Node, p.Instance)
				continue
			}
			s.DB.Exec(ctx, "DELETE FROM certificate_links WHERE node_id=$1 AND instance_id=$2", p.Node, p.Instance)
		}
		for _, g := range q.Updates {
			if q.Action == "revoke" {
				s.DB.Exec(ctx, "UPDATE tunnels SET managed=false,revision=revision+1,health='{}',updated=now() WHERE id=$1", g.ID)
			} else {
				s.DB.Exec(ctx, "DELETE FROM tunnels WHERE id=$1", g.ID)
			}
		}
	} else {
		for _, g := range q.Updates {
			s.DB.Exec(ctx, "UPDATE tunnels SET desired=$1,updated=now() WHERE id=$2", desired, g.ID)
		}
	}
	s.phase(ctx, id, "succeeded", map[string]any{"affected_tunnels": publicAffected(q)}, nil)
}
func (s *Server) processAdoption(ctx context.Context, id string, q JobPayload) {
	s.phase(ctx, id, "running", nil, nil)
	privateConfigs := map[string]string{}
	for _, p := range s.changeParts(q) {
		var inventory []byte
		if s.DB.QueryRow(ctx, "SELECT inventory FROM nodes WHERE id=$1", p.Node).Scan(&inventory) != nil {
			s.phase(ctx, id, "failed", nil, errors.New("discover_node_first"))
			return
		}
		var value struct {
			Instances []nodeops.Discovered `json:"instances"`
		}
		json.Unmarshal(inventory, &value)
		var selected *nodeops.Discovered
		for i := range value.Instances {
			if value.Instances[i].ID == q.Instances[p.Node] {
				selected = &value.Instances[i]
				break
			}
		}
		if selected == nil {
			s.phase(ctx, id, "failed", nil, errors.New("discovered_instance_missing"))
			return
		}
		if q.Hashes[p.Node] != selected.Hash {
			s.phase(ctx, id, "failed", nil, errors.New("rediscover_and_import_changed_configuration_before_adoption"))
			return
		}
		v, e := s.command(ctx, id, p.Node, "adopt", "instance.adopt", map[string]any{"ID": selected.ID, "Hash": selected.Hash, "Fingerprint": selected.Fingerprint, "DefinitionHash": selected.DefinitionHash, "Confirm": true})
		if e != nil {
			s.phase(ctx, id, "failed", nil, e)
			return
		}
		var result struct {
			Private string `json:"private_configuration"`
		}
		json.Unmarshal(v.Data, &result)
		privateConfigs[p.Role] = result.Private
		q.Hashes[p.Node] = selected.Hash
	}
	if e := engine.ImportSecrets(&q.Spec, privateConfigs["server"], privateConfigs["client"]); e != nil {
		s.phase(ctx, id, "failed", nil, e)
		return
	}
	record := TunnelRecord{Spec: q.Spec, Instances: q.Instances, Hashes: q.Hashes}
	cipher, e := s.sealValue("tunnel:"+q.Tunnel, record)
	if e != nil {
		s.phase(ctx, id, "failed", nil, e)
		return
	}
	tag, e := s.DB.Exec(ctx, "UPDATE tunnels SET managed=true,cipher=$1,revision=revision+1,updated=now() WHERE id=$2 AND revision=$3", cipher, q.Tunnel, q.ExpectedRevision)
	if e != nil || tag.RowsAffected() != 1 {
		s.phase(ctx, id, "failed", nil, errors.New("adoption_revision_changed"))
		return
	}
	s.phase(ctx, id, "succeeded", map[string]any{"adopted": true, "files_changed": false}, nil)
}
