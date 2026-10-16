package controller

import (
	"context"
	"encoding/base64"
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
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *Server) sealValue(purpose string, v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	return secure.Seal(s.Config.Key, purpose, b)
}
func (s *Server) openValue(purpose string, b []byte, v any) error {
	raw, e := secure.Open(s.Config.Key, purpose, b)
	if e != nil {
		return errors.New("encrypted_state_unavailable")
	}
	return json.Unmarshal(raw, v)
}
func (s *Server) acceptResults(ctx context.Context, node string, results []protocol.Result) error {
	if len(results) > 1 {
		return errors.New("too_many_results")
	}
	for _, result := range results {
		if !engine.ID(result.ID) || len(result.Code) > 200 || len(result.Data) > 192*1024 {
			return errors.New("invalid_result")
		}
		cipher, e := s.sealValue("result:"+result.ID, result)
		if e != nil {
			return e
		}
		_, e = s.DB.Exec(ctx, "UPDATE commands SET state='completed',result_cipher=$1 WHERE id=$2 AND node_id=$3 AND state IN ('queued','delivered')", cipher, result.ID, node)
		if e != nil {
			return e
		}
	}
	return nil
}
func (s *Server) deliverCommand(ctx context.Context, node string) *protocol.Command {
	var id, kind string
	var cipher []byte
	var expires time.Time
	e := s.DB.QueryRow(ctx, `UPDATE commands SET state='delivered',lease_until=now()+interval '75 seconds' WHERE id=(SELECT id FROM commands WHERE node_id=$1 AND expires>now() AND (state='queued' OR (state='delivered' AND lease_until<now())) AND NOT EXISTS(SELECT 1 FROM commands c WHERE c.node_id=$1 AND c.state='delivered' AND c.lease_until>now() AND c.expires>now()) ORDER BY created LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING id,kind,cipher,expires`, node).Scan(&id, &kind, &cipher, &expires)
	if e != nil {
		return nil
	}
	var payload json.RawMessage
	if s.openValue("command:"+id, cipher, &payload) != nil {
		return nil
	}
	return &protocol.Command{ID: id, Kind: kind, Expires: expires, Payload: payload}
}
func (s *Server) command(ctx context.Context, op, node, stage, kind string, payload any) (protocol.Result, error) {
	id := secure.Token(18)
	cipher, e := s.sealValue("command:"+id, payload)
	if e != nil {
		return protocol.Result{}, e
	}
	var approved bool
	var protocolVersion int
	if e = s.DB.QueryRow(ctx, "SELECT approved,protocol FROM nodes WHERE id=$1", node).Scan(&approved, &protocolVersion); e != nil || !approved {
		return protocol.Result{}, errors.New("node_not_approved")
	}
	if protocolVersion < 2 {
		return protocol.Result{}, errors.New("upgrade_node_agent_before_management")
	}
	if !s.isConnected(node) {
		var cached []byte
		var cachedID string
		if s.DB.QueryRow(ctx, "SELECT id,result_cipher FROM commands WHERE operation_id=$1 AND node_id=$2 AND stage=$3 AND state='completed'", op, node, stage).Scan(&cachedID, &cached) == nil {
			var result protocol.Result
			if s.openValue("result:"+cachedID, cached, &result) == nil {
				if result.OK {
					return result, nil
				}
				return result, errors.New(result.Code)
			}
		}
		return protocol.Result{}, errors.New("node_offline")
	}
	_, e = s.DB.Exec(ctx, "INSERT INTO commands(id,operation_id,node_id,stage,kind,cipher,expires)VALUES($1,$2,$3,$4,$5,$6,now()+interval '3 minutes') ON CONFLICT(operation_id,node_id,stage) DO NOTHING", id, op, node, stage, kind, cipher)
	if e != nil {
		return protocol.Result{}, e
	}
	var actualID string
	var expires time.Time
	if e = s.DB.QueryRow(ctx, "SELECT id,expires FROM commands WHERE operation_id=$1 AND node_id=$2 AND stage=$3", op, node, stage).Scan(&actualID, &expires); e != nil {
		return protocol.Result{}, e
	}
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	for {
		var state string
		var result []byte
		if e = s.DB.QueryRow(ctx, "SELECT state,result_cipher FROM commands WHERE id=$1", actualID).Scan(&state, &result); e != nil {
			return protocol.Result{}, e
		}
		if state == "completed" {
			var value protocol.Result
			if e = s.openValue("result:"+actualID, result, &value); e != nil {
				return value, e
			}
			if !value.OK {
				return value, errors.New(value.Code)
			}
			return value, nil
		}
		if time.Now().After(expires) {
			return protocol.Result{}, errors.New("node_command_expired")
		}
		if !s.isConnected(node) {
			return protocol.Result{}, errors.New("node_offline")
		}
		select {
		case <-ctx.Done():
			return protocol.Result{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

type JobPayload struct {
	PreserveCurrent  bool              `json:"preserve_current,omitempty"`
	RecoveryAttempt  int               `json:"recovery_attempt,omitempty"`
	FailureCode      string            `json:"failure_code,omitempty"`
	AwaitTelegram    bool              `json:"await_telegram,omitempty"`
	TelegramReply    bool              `json:"telegram_reply,omitempty"`
	Parts            []ChangePart      `json:"parts,omitempty"`
	Updates          []TunnelUpdate    `json:"updates,omitempty"`
	Certificate      string            `json:"certificate,omitempty"`
	RequestHash      string            `json:"request_hash,omitempty"`
	Deadline         time.Time         `json:"deadline,omitempty"`
	Node             string            `json:"node,omitempty"`
	Kind             string            `json:"kind,omitempty"`
	Payload          json.RawMessage   `json:"payload,omitempty"`
	Spec             engine.Spec       `json:"spec,omitempty"`
	Tunnel           string            `json:"tunnel,omitempty"`
	Name             string            `json:"name,omitempty"`
	ExpectedRevision int64             `json:"expected_revision,omitempty"`
	Instances        map[string]string `json:"instances,omitempty"`
	Hashes           map[string]string `json:"hashes,omitempty"`
	Sources          map[string]string `json:"sources,omitempty"`
	Action           string            `json:"action,omitempty"`
	Confirm          bool              `json:"confirm,omitempty"`
}

func (s *Server) newJob(ctx context.Context, key, kind, target, name string, payload JobPayload) (string, error) {
	if !engine.ID(key) {
		return "", errors.New("request_key_required")
	}
	id := secure.Token(18)
	cipher, e := s.sealValue("operation:"+id, payload)
	if e != nil {
		return "", e
	}
	var existing string
	if payload.RequestHash == "" {
		raw, _ := json.Marshal(payload)
		payload.RequestHash = secure.Hash(string(s.Config.Key) + kind + target + name + string(raw))
	}
	initial := "queued"
	if payload.AwaitTelegram {
		initial = "awaiting_telegram"
	}
	e = s.DB.QueryRow(ctx, "INSERT INTO operations(id,request_key,kind,target,name,cipher,request_hash,phase)VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(request_key) DO UPDATE SET request_key=EXCLUDED.request_key WHERE operations.request_hash=EXCLUDED.request_hash RETURNING id", id, key, kind, target, name, cipher, payload.RequestHash, initial).Scan(&existing)
	if e != nil {
		var dbError *pgconn.PgError
		if errors.As(e, &dbError) && strings.HasPrefix(dbError.ConstraintName, "operations_one_certificate_change") {
			return "", errors.New("certificate_operation_in_progress")
		}
		return "", errors.New("request_key_reused_with_different_input")
	}
	if e == nil {
		s.Audit(ctx, "operation-created", name, kind)
	}
	return existing, e
}
func (s *Server) step(ctx context.Context, id, stage, node, status, code string) {
	event, _ := json.Marshal([]map[string]any{{"stage": stage, "node": node, "status": status, "code": code, "at": time.Now().UTC()}})
	s.DB.Exec(ctx, "UPDATE operations SET steps=(SELECT jsonb_agg(value ORDER BY ord) FROM(SELECT value,ord FROM jsonb_array_elements(steps||$1::jsonb) WITH ORDINALITY a(value,ord) ORDER BY ord DESC LIMIT 200)a),updated=now() WHERE id=$2", event, id)
}
func (s *Server) phase(ctx context.Context, id, phase string, result any, err error) {
	code := ""
	if err != nil {
		code = short(err.Error(), 200)
	}
	b, _ := json.Marshal(result)
	if result != nil {
		b, _ = json.Marshal(publicData(b))
	}
	if result == nil {
		b = []byte("{}")
	}
	s.DB.Exec(ctx, "UPDATE operations SET phase=$1,result=$2,error=$3,updated=now() WHERE id=$4", phase, b, code, id)
	if phase == "failed" || phase == "succeeded" || phase == "reverted" {
		s.Audit(ctx, "operation-"+phase, id, code)
	}
}
func (s *Server) Operations(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	slots := make(chan struct{}, 2)
	running := map[string]bool{}
	done := make(chan string, 2)
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-done:
			delete(running, id)
		case <-ticker.C:
			s.DB.Exec(ctx, "UPDATE operations SET phase='expired',error='telegram_confirmation_expired',updated=now() WHERE phase='awaiting_telegram' AND NOT EXISTS(SELECT 1 FROM telegram_actions t WHERE t.operation_id=operations.id AND t.expires>now() AND NOT t.consumed) AND created<now()-interval '2 minutes'")
			s.DB.Exec(ctx, "UPDATE operations SET phase='reverting',updated=now() WHERE kind='plan' AND phase='awaiting_confirmation' AND deadline<now()")
			s.DB.Exec(ctx, "UPDATE operations SET phase='expired',updated=now() WHERE phase='ready' AND updated<now()-interval '10 minutes'")
			rows, e := s.DB.Query(ctx, "SELECT id FROM operations WHERE phase IN ('queued','applying','confirming','reverting','running') OR(phase IN('recovery_pending','release_pending') AND updated<now()-interval '30 seconds') ORDER BY created LIMIT 30")
			if e != nil {
				continue
			}
			ids := []string{}
			for rows.Next() {
				var id string
				rows.Scan(&id)
				ids = append(ids, id)
			}
			rows.Close()
			for _, id := range ids {
				if running[id] {
					continue
				}
				select {
				case slots <- struct{}{}:
					running[id] = true
					go func(id string) { defer func() { <-slots; done <- id }(); s.processJob(ctx, id) }(id)
				default:
				}
			}
		}
	}
}
func (s *Server) processJob(parent context.Context, id string) {
	ctx, cancel := context.WithTimeout(parent, 9*time.Minute)
	defer cancel()
	conn, e := s.DB.Acquire(ctx)
	if e != nil {
		return
	}
	defer conn.Release()
	var locked bool
	if conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtext($1))", id).Scan(&locked) != nil || !locked {
		return
	}
	defer conn.Exec(context.Background(), "SELECT pg_advisory_unlock(hashtext($1))", id)
	var kind, phase string
	var cipher []byte
	e = s.DB.QueryRow(ctx, "SELECT kind,phase,cipher FROM operations WHERE id=$1", id).Scan(&kind, &phase, &cipher)
	if e != nil {
		return
	}
	var q JobPayload
	if s.openValue("operation:"+id, cipher, &q) != nil {
		s.phase(ctx, id, "failed", nil, errors.New("operation_decryption_failed"))
		return
	}
	defer s.notifyOperation(context.WithoutCancel(ctx), id, q)
	if q.PreserveCurrent {
		s.processRecoveryRelease(ctx, id, q)
		return
	}
	switch kind {
	case "node":
		s.phase(ctx, id, "running", nil, nil)
		s.step(ctx, id, q.Kind, q.Node, "running", "")
		result, e := s.command(ctx, id, q.Node, "action", q.Kind, q.Payload)
		if e != nil {
			s.step(ctx, id, q.Kind, q.Node, "failed", e.Error())
			s.phase(ctx, id, "failed", nil, e)
			return
		}
		s.step(ctx, id, q.Kind, q.Node, "succeeded", "")
		s.consumeNodeResult(ctx, q.Node, q.Kind, q.Payload, result)
		s.phase(ctx, id, "succeeded", publicData(result.Data), nil)
	case "plan":
		s.processPlan(ctx, id, phase, q)
	case "adopt":
		s.processAdoption(ctx, id, q)
	case "tunnel-action":
		s.processTunnelAction(ctx, id, q)
	case "tunnel-check":
		s.processTunnelCheck(ctx, id, q)
	case "certificate":
		s.processCertificate(ctx, id, q)
	default:
		s.phase(ctx, id, "failed", nil, errors.New("unsupported_operation_kind"))
	}
}
func publicData(raw json.RawMessage) any {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	var redact func(any) any
	redact = func(value any) any {
		switch x := value.(type) {
		case map[string]any:
			for k, v := range x {
				lower := strings.ToLower(k)
				if strings.Contains(lower, "private") || strings.Contains(lower, "token") || lower == "key" || strings.Contains(lower, "password") || lower == "auth_match" {
					delete(x, k)
				} else {
					x[k] = redact(v)
				}
			}
		case []any:
			for i, v := range x {
				x[i] = redact(v)
			}
		}
		return value
	}
	return redact(v)
}
func (s *Server) consumeNodeResult(ctx context.Context, node, kind string, payload json.RawMessage, result protocol.Result) {
	if kind == "inventory" {
		s.DB.Exec(ctx, "UPDATE nodes SET inventory=$1,inventory_at=now() WHERE id=$2", result.Data, node)
		s.reconcileDiscovery(ctx)
	}
	if kind == "diagnostic" {
		var q struct {
			Kind     string          `json:"kind"`
			Endpoint engine.Endpoint `json:"endpoint"`
		}
		json.Unmarshal(payload, &q)
		s.DB.Exec(ctx, "INSERT INTO checks(node_id,target,kind,data)VALUES($1,$2,$3,$4)", node, q.Endpoint.String(), q.Kind, result.Data)
	}
	if kind == "instance.action" || kind == "recovery.policy" || kind == "logs.verbosity" || kind == "logs.release" || kind == "instance.adopt" {
		s.DB.Exec(ctx, "UPDATE nodes SET inventory_at=NULL WHERE id=$1", node)
	}
	if kind == "recovery.policy" {
		var policy struct {
			ID string `json:"id"`
		}
		json.Unmarshal(payload, &policy)
		if policy.ID != "" {
			s.DB.Exec(ctx, "INSERT INTO recovery_rules(node_id,instance_id,policy)VALUES($1,$2,$3)ON CONFLICT(node_id,instance_id)DO UPDATE SET policy=EXCLUDED.policy", node, policy.ID, result.Data)
		}
	}
	if kind == "instance.adopt" {
		var input struct{ ID string }
		json.Unmarshal(payload, &input)
		for _, t := range s.affected(ctx, node, input.ID) {
			s.DB.Exec(ctx, "UPDATE tunnels SET managed=false,revision=revision+1,health='{}',updated=now() WHERE id=$1", t["id"])
		}
	}
	if kind == "instance.action" {
		var action struct{ ID, Action string }
		json.Unmarshal(payload, &action)
		s.invalidateHealth(ctx, node, action.ID, "service_action_requires_new_check")
		if action.Action == "revoke" {
			s.freezeCertificateLinks(ctx, node, action.ID)
		}
		if action.Action == "remove" {
			s.DB.Exec(ctx, "DELETE FROM certificate_links WHERE node_id=$1 AND instance_id=$2", node, action.ID)
		}
		desired := "running"
		if action.Action == "stop" || action.Action == "disable" {
			desired = action.Action
		}
		for _, t := range s.affected(ctx, node, action.ID) {
			if action.Action == "revoke" {
				s.DB.Exec(ctx, "UPDATE tunnels SET managed=false,revision=revision+1,health='{}',updated=now() WHERE id=$1", t["id"])
				continue
			}
			if action.Action == "remove" {
				s.DB.Exec(ctx, "DELETE FROM tunnels WHERE id=$1", t["id"])
				continue
			}
			s.DB.Exec(ctx, "UPDATE tunnels SET desired=$1 WHERE id=$2", desired, t["id"])
		}
	}
}
func (s *Server) operationList(w http.ResponseWriter, r *http.Request) {
	rows, e := s.DB.Query(r.Context(), `SELECT id,kind,target,name,phase,error,created,updated,deadline,COALESCE(result->>'status',CASE WHEN kind='tunnel-check' THEN CASE WHEN result->'transport'->>'status'='failed' OR result->'tls'->>'status'='failed' OR result->'application'->>'status'='failed' THEN 'failed' WHEN result->'application'->>'status'='unconfigured' THEN 'partial' ELSE result->'application'->>'status' END END) FROM operations ORDER BY created DESC LIMIT 100`)
	if e != nil {
		fail(w, 503, "operations_unavailable", "Retry shortly.", "کمی بعد دوباره تلاش کنید.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, kind, target, name, phase, code string
		var created, updated time.Time
		var deadline *time.Time
		var check *string
		rows.Scan(&id, &kind, &target, &name, &phase, &code, &created, &updated, &deadline, &check)
		items = append(items, map[string]any{"id": id, "kind": kind, "target": target, "name": name, "phase": phase, "error": code, "created": created, "updated": updated, "deadline": deadline, "check_status": check})
	}
	write(w, items)
}
func (s *Server) operationDetail(w http.ResponseWriter, r *http.Request) {
	var id, kind, target, name, phase, code string
	var steps, result, cipher []byte
	var deadline *time.Time
	e := s.DB.QueryRow(r.Context(), "SELECT id,kind,target,name,phase,error,steps,result,deadline,cipher FROM operations WHERE id=$1", r.PathValue("id")).Scan(&id, &kind, &target, &name, &phase, &code, &steps, &result, &deadline, &cipher)
	if e != nil {
		fail(w, 404, "operation_missing", "Operation not found.", "عملیات پیدا نشد.")
		return
	}
	var q JobPayload
	s.openValue("operation:"+id, cipher, &q)
	write(w, map[string]any{"id": id, "kind": kind, "target": target, "name": name, "phase": phase, "error": code, "steps": json.RawMessage(steps), "result": json.RawMessage(result), "deadline": deadline, "affected_tunnels": publicAffected(q)})
}
func (s *Server) nodeAction(w http.ResponseWriter, r *http.Request) {
	var q struct {
		RequestKey string          `json:"request_key"`
		Kind       string          `json:"kind"`
		Payload    json.RawMessage `json:"payload"`
		Confirm    bool            `json:"confirm"`
	}
	if !decode(w, r, &q) {
		return
	}
	allowed := map[string]bool{"inventory": true, "engine.install": true, "instance.config": true, "instance.status": true, "tools.status": true, "instance.action": true, "instance.adopt": true, "logs.read": true, "logs.verbosity": true, "logs.release": true, "diagnostic": true, "recovery.policy": true}
	if !allowed[q.Kind] {
		fail(w, 400, "typed_action_required", "Select an available action.", "یکی از عملیات مجاز را انتخاب کنید.")
		return
	}
	if (q.Kind == "logs.release" || q.Kind == "instance.adopt" || q.Kind == "logs.verbosity" || q.Kind == "engine.install" || q.Kind == "recovery.policy" || q.Kind == "instance.action") && !q.Confirm {
		fail(w, 400, "confirmation_required", "Review and confirm this change.", "اثر تغییر را بررسی و تأیید کنید.")
		return
	}
	if q.Kind == "instance.adopt" {
		var input struct{ ID, Name string }
		var raw []byte
		var at *time.Time
		if json.Unmarshal(q.Payload, &input) != nil || len(input.Name) > 100 {
			badOperation(w, errors.New("invalid_instance_selection"))
			return
		}
		if s.DB.QueryRow(r.Context(), "SELECT inventory,inventory_at FROM nodes WHERE id=$1", r.PathValue("id")).Scan(&raw, &at) != nil || at == nil || time.Since(*at) > 5*time.Minute {
			badOperation(w, errors.New("rediscover_before_adoption"))
			return
		}
		var inventory struct {
			Instances []nodeops.Discovered `json:"instances"`
		}
		json.Unmarshal(raw, &inventory)
		var selected *nodeops.Discovered
		for i := range inventory.Instances {
			if inventory.Instances[i].ID == input.ID {
				selected = &inventory.Instances[i]
				break
			}
		}
		if selected == nil {
			badOperation(w, errors.New("discovered_instance_missing"))
			return
		}
		q.Payload, _ = json.Marshal(map[string]any{"ID": selected.ID, "Name": input.Name, "Hash": selected.Hash, "Fingerprint": selected.Fingerprint, "DefinitionHash": selected.DefinitionHash, "Confirm": true})
	}
	if q.Kind == "inventory" {
		key := secure.Hash(string(s.Config.Key) + "discovery-match-v1")
		b, _ := json.Marshal(map[string]string{"MatchKey": base64.RawURLEncoding.EncodeToString([]byte(key)[:32])})
		q.Payload = b
	}
	if len(q.Payload) == 0 {
		q.Payload = []byte("{}")
	}
	id, e := s.newJob(r.Context(), q.RequestKey, "node", r.PathValue("id"), q.Kind, JobPayload{Node: r.PathValue("id"), Kind: q.Kind, Payload: q.Payload})
	if e != nil {
		fail(w, 400, "invalid_operation", e.Error(), "سرور و شناسهٔ درخواست را بررسی کنید.")
		return
	}
	write(w, map[string]string{"operation_id": id})
}
func (s *Server) engineCatalog(w http.ResponseWriter, r *http.Request) { write(w, engine.Catalog) }
func (s *Server) nodeInventory(w http.ResponseWriter, r *http.Request) {
	var inventory []byte
	var at *time.Time
	if s.DB.QueryRow(r.Context(), "SELECT inventory,inventory_at FROM nodes WHERE id=$1", r.PathValue("id")).Scan(&inventory, &at) != nil {
		fail(w, 404, "node_missing", "Node missing.", "سرور پیدا نشد.")
		return
	}
	write(w, map[string]any{"data": publicData(inventory), "at": at, "fresh": at != nil && time.Since(*at) < 5*time.Minute})
}
func badOperation(w http.ResponseWriter, e error) {
	fail(w, 400, "operation_blocked", fmt.Sprint(e), "عملیات انجام نشد؛ جزئیات خطا را بررسی و دوباره تلاش کنید.")
}
