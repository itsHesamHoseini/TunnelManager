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
	defer rows.Close()
	items := []map[string]any{}
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
	}
	write(w, items)
}
func (s *Server) tunnelDetail(w http.ResponseWriter, r *http.Request) {
	record, revision, managed, e := s.readTunnel(r.Context(), r.PathValue("id"))
	if e != nil {
		badOperation(w, e)
		return
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
	write(w, map[string]any{"id": r.PathValue("id"), "revision": revision, "managed": managed, "spec": engine.Public(record.Spec), "instances": record.Instances, "hashes": record.Hashes, "versions": versions})
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
	if instances[q.Spec.Listener] == "" {
		instances[q.Spec.Listener] = id + "_s"
	}
	if instances[q.Spec.Dialer] == "" {
		instances[q.Spec.Dialer] = id + "_c"
	}
	op, e := s.newJob(r.Context(), q.RequestKey, "plan", id, q.Name, JobPayload{RequestHash: requestHash, Spec: q.Spec, Tunnel: id, Name: q.Name, ExpectedRevision: q.ExpectedRevision, Instances: instances, Hashes: hashes})
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
	} else if q.Action != "apply" {
		badOperation(w, errors.New("invalid_plan_action"))
		return
	}
	tag, e := s.DB.Exec(r.Context(), "UPDATE operations SET phase=$1,updated=now() WHERE id=$2 AND kind='plan' AND phase=$3", to, r.PathValue("id"), from)
	if e != nil || tag.RowsAffected() != 1 {
		badOperation(w, errors.New("operation_state_changed"))
		return
	}
	s.Audit(r.Context(), "change-"+q.Action, r.PathValue("id"), "explicitly-confirmed")
	write(w, map[string]bool{"accepted": true})
}
func (s *Server) changeParts(q JobPayload) []struct{ Node, Role string } {
	return []struct{ Node, Role string }{{q.Spec.Listener, "server"}, {q.Spec.Dialer, "client"}}
}
func (s *Server) processPlan(ctx context.Context, id, phase string, q JobPayload) {
	parts := s.changeParts(q)
	runPart := func(p struct{ Node, Role string }, stage, kind string, payload any) (protocol.Result, error) {
		s.step(ctx, id, stage, p.Node, "running", "")
		v, e := s.command(ctx, id, p.Node, stage, kind, payload)
		status := "succeeded"
		code := ""
		if e != nil {
			status = "failed"
			code = e.Error()
		}
		s.step(ctx, id, stage, p.Node, status, code)
		return v, e
	}
	fail := func(e error) {
		recovery := []map[string]any{}
		for _, p := range parts {
			_, re := s.command(ctx, id, p.Node, "rollback", "change.rollback", map[string]any{"ID": id, "Compensate": true})
			recovery = append(recovery, map[string]any{"node": p.Node, "restored": re == nil})
		}
		s.DB.Exec(ctx, "DELETE FROM port_reservations WHERE plan_id=$1", id)
		s.phase(ctx, id, "failed", map[string]any{"recovery": recovery, "local_rollback": "armed on unconfirmed nodes; unreachable confirmed peers require reconciliation"}, e)
	}
	switch phase {
	case "queued", "running":
		s.phase(ctx, id, "running", nil, nil)
		previews := map[string]any{}
		for _, p := range parts {
			c := nodeops.Change{ID: id, Instance: q.Instances[p.Node], Name: q.Name, Role: p.Role, ExpectedHash: q.Hashes[p.Node], Spec: q.Spec}
			v, e := runPart(p, "preflight", "change.preflight", c)
			if e != nil {
				s.phase(ctx, id, "failed", nil, e)
				return
			}
			var out map[string]any
			json.Unmarshal(v.Data, &out)
			previews[p.Node] = out
			if good, _ := out["valid"].(bool); !good {
				s.phase(ctx, id, "failed", previews, errors.New("preflight_blocked"))
				return
			}
		}
		if e := s.reserve(ctx, id, q); e != nil {
			s.phase(ctx, id, "failed", previews, e)
			return
		}
		s.phase(ctx, id, "ready", map[string]any{"previews": previews, "affected_routes": q.Spec.Routes, "reverse_connection": map[string]string{"from": q.Spec.Dialer, "to": q.Spec.Listener}, "notice": "activation restarts the selected shared units; application health is checked separately"}, nil)
	case "applying":
		if q.ExpectedRevision > 0 {
			_, revision, _, e := s.readTunnel(ctx, q.Tunnel)
			if e != nil || revision != q.ExpectedRevision {
				fail(errors.New("tunnel_revision_changed"))
				return
			}
		}
		for _, p := range parts {
			c := nodeops.Change{ID: id, Instance: q.Instances[p.Node], Name: q.Name, Role: p.Role, ExpectedHash: q.Hashes[p.Node], Spec: q.Spec, Deadline: time.Now().Add(5 * time.Minute)}
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
		for _, p := range parts {
			v, e := runPart(p, "activate", "change.activate", map[string]any{"ID": id, "Deadline": deadline})
			if e != nil {
				fail(e)
				return
			}
			var out struct {
				Instance nodeops.Instance `json:"instance"`
				Active   bool             `json:"process_active"`
			}
			json.Unmarshal(v.Data, &out)
			if !out.Active && !out.Instance.Stopped {
				fail(errors.New("engine_process_not_active"))
				return
			}
			if q.Hashes == nil {
				q.Hashes = map[string]string{}
			}
			q.Hashes[p.Node] = out.Instance.Hash
		}
		cipher, e := s.sealValue("operation:"+id, q)
		if e != nil {
			fail(e)
			return
		}
		s.DB.Exec(ctx, "UPDATE operations SET cipher=$1 WHERE id=$2", cipher, id)
		s.phase(ctx, id, "awaiting_confirmation", map[string]any{"affected_routes": q.Spec.Routes, "deadline": deadline, "process": "active", "transport": "not_yet_tested", "application": "not_configured"}, nil)
	case "confirming":
		var deadline *time.Time
		s.DB.QueryRow(ctx, "SELECT deadline FROM operations WHERE id=$1", id).Scan(&deadline)
		if deadline == nil || deadline.Before(time.Now()) {
			fail(errors.New("confirmation_deadline_expired"))
			return
		}
		for _, p := range parts {
			if _, e := runPart(p, "confirm", "change.confirm", map[string]string{"ID": id}); e != nil {
				fail(e)
				return
			}
		}
		for _, p := range parts {
			if _, e := runPart(p, "commit", "change.confirm", map[string]any{"ID": id, "Commit": true}); e != nil {
				fail(e)
				return
			}
		}
		record := TunnelRecord{Spec: q.Spec, Instances: q.Instances, Hashes: q.Hashes}
		cipher, e := s.sealValue("tunnel:"+q.Tunnel, record)
		if e != nil {
			fail(e)
			return
		}
		tx, e := s.DB.Begin(ctx)
		if e != nil {
			fail(e)
			return
		}
		defer tx.Rollback(ctx)
		if q.ExpectedRevision == 0 {
			_, e = tx.Exec(ctx, "INSERT INTO tunnels(id,name,cipher,managed)VALUES($1,$2,$3,true)", q.Tunnel, q.Name, cipher)
		} else {
			tag, err := tx.Exec(ctx, "UPDATE tunnels SET name=$1,cipher=$2,revision=revision+1,updated=now() WHERE id=$3 AND revision=$4", q.Name, cipher, q.Tunnel, q.ExpectedRevision)
			e = err
			if e == nil && tag.RowsAffected() != 1 {
				e = errors.New("tunnel_revision_changed")
			}
		}
		if e == nil {
			_, e = tx.Exec(ctx, "INSERT INTO tunnel_versions(tunnel_id,revision,cipher)VALUES($1,$2,$3)", q.Tunnel, q.ExpectedRevision+1, cipher)
		}
		if e == nil {
			_, e = tx.Exec(ctx, "DELETE FROM port_reservations WHERE plan_id=$1", id)
		}
		if e != nil || tx.Commit(ctx) != nil {
			s.phase(ctx, id, "failed", nil, errors.New("confirmation_database_commit_requires_reconciliation"))
			return
		}
		s.phase(ctx, id, "succeeded", map[string]any{"tunnel_id": q.Tunnel, "revision": q.ExpectedRevision + 1}, nil)
	case "reverting":
		for _, p := range parts {
			if _, e := runPart(p, "rollback", "change.rollback", map[string]string{"ID": id}); e != nil {
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
	if !strings.Contains("|start|stop|restart|reload|disable|remove|", "|"+q.Action+"|") {
		badOperation(w, errors.New("invalid_action"))
		return
	}
	id, e := s.newJob(r.Context(), q.RequestKey, "tunnel-action", r.PathValue("id"), q.Action, JobPayload{Tunnel: r.PathValue("id"), Spec: record.Spec, Instances: record.Instances, Hashes: record.Hashes, Action: q.Action, ExpectedRevision: rev, Confirm: true})
	if e != nil {
		badOperation(w, e)
		return
	}
	write(w, map[string]any{"operation_id": id, "affected_routes": record.Spec.Routes})
}
func (s *Server) processTunnelAction(ctx context.Context, id string, q JobPayload) {
	s.phase(ctx, id, "running", nil, nil)
	for _, p := range s.changeParts(q) {
		s.step(ctx, id, q.Action, p.Node, "running", "")
		_, e := s.command(ctx, id, p.Node, "action", "instance.action", map[string]any{"ID": q.Instances[p.Node], "Action": q.Action, "ExpectedHash": q.Hashes[p.Node], "Confirm": true})
		if e != nil {
			s.phase(ctx, id, "failed", map[string]any{"partial": true, "affected_routes": q.Spec.Routes}, e)
			return
		}
		s.step(ctx, id, q.Action, p.Node, "succeeded", "")
	}
	desired := "running"
	if q.Action == "stop" || q.Action == "disable" {
		desired = q.Action
	}
	if q.Action == "remove" {
		s.DB.Exec(ctx, "DELETE FROM tunnels WHERE id=$1", q.Tunnel)
	} else {
		s.DB.Exec(ctx, "UPDATE tunnels SET desired=$1,updated=now() WHERE id=$2", desired, q.Tunnel)
	}
	s.phase(ctx, id, "succeeded", map[string]any{"affected_routes": q.Spec.Routes}, nil)
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
		v, e := s.command(ctx, id, p.Node, "adopt", "instance.adopt", map[string]any{"ID": selected.ID, "Hash": selected.Hash, "Fingerprint": selected.Fingerprint, "Confirm": true})
		if e != nil {
			s.phase(ctx, id, "failed", nil, e)
			return
		}
		var result struct {
			Private string `json:"private_configuration"`
		}
		json.Unmarshal(v.Data, &result)
		privateConfigs[p.Role] = result.Private
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
