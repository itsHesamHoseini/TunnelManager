package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/itsHesamHoseini/TunnelManager/internal/nodeops"
	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
	"net/http"
	"time"
)

func (s *Server) Monitor(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.scheduleMonitoring(ctx)
			s.evaluateAlerts(ctx)
			s.scheduleRenewals(ctx)
			s.scheduleCertificateDeployments(ctx)
		}
	}
}
func (s *Server) scheduleMonitoring(ctx context.Context) {
	nodeRows, err := s.DB.Query(ctx, "SELECT id FROM nodes WHERE approved AND protocol=2 AND seen>now()-interval '90 seconds' AND (inventory_at IS NULL OR inventory_at<now()-interval '5 minutes') AND NOT EXISTS(SELECT 1 FROM operations o WHERE o.target=nodes.id AND o.name='inventory' AND o.phase IN('queued','running')) ORDER BY inventory_at NULLS FIRST LIMIT 2")
	if err == nil {
		ids := []string{}
		for nodeRows.Next() {
			var node string
			nodeRows.Scan(&node)
			ids = append(ids, node)
		}
		nodeRows.Close()
		match := secure.Hash(string(s.Config.Key) + "discovery-match-v1")
		payload, _ := json.Marshal(map[string]string{"MatchKey": base64.RawURLEncoding.EncodeToString([]byte(match)[:32])})
		for _, node := range ids {
			s.newJob(ctx, fmt.Sprintf("inventory_%s_%d", node, time.Now().Unix()/30), "node", node, "inventory", JobPayload{Node: node, Kind: "inventory", Payload: payload})
		}
	}
	rows, e := s.DB.Query(ctx, `SELECT id,name FROM tunnels WHERE desired='running' AND NOT EXISTS(SELECT 1 FROM operations o WHERE o.target=tunnels.id AND o.kind IN('plan','tunnel-action','tunnel-check') AND o.phase IN('queued','running','applying','awaiting_confirmation','confirming','reverting')) AND NOT EXISTS(SELECT 1 FROM operations o WHERE o.target=tunnels.id AND o.kind='tunnel-check' AND o.created>now()-interval '2 minutes') ORDER BY updated LIMIT 10`)
	if e != nil {
		return
	}
	type item struct{ id, name string }
	items := []item{}
	for rows.Next() {
		var v item
		rows.Scan(&v.id, &v.name)
		items = append(items, v)
	}
	rows.Close()
	for _, v := range items {
		s.newJob(ctx, fmt.Sprintf("monitor_%s_%d", v.id, time.Now().Unix()/120), "tunnel-check", v.id, v.name, JobPayload{Tunnel: v.id})
	}
}
func (s *Server) tunnelCheck(w http.ResponseWriter, r *http.Request) {
	var q struct{ RequestKey string }
	if !decode(w, r, &q) {
		return
	}
	if _, _, _, e := s.readTunnel(r.Context(), r.PathValue("id")); e != nil {
		badOperation(w, e)
		return
	}
	id, e := s.newJob(r.Context(), q.RequestKey, "tunnel-check", r.PathValue("id"), "Check tunnel", JobPayload{Tunnel: r.PathValue("id")})
	if e != nil {
		badOperation(w, e)
		return
	}
	write(w, map[string]string{"operation_id": id})
}
func (s *Server) processTunnelCheck(ctx context.Context, id string, q JobPayload) {
	rec, _, _, e := s.readTunnel(ctx, q.Tunnel)
	if q.Kind == "pending-plan" {
		rec = TunnelRecord{Spec: q.Spec, Instances: q.Instances, Hashes: q.Hashes}
		e = nil
	}
	if e != nil {
		s.phase(ctx, id, "failed", nil, e)
		return
	}
	s.phase(ctx, id, "running", nil, nil)
	out := map[string]any{"at": time.Now().UTC(), "application": map[string]any{"status": "unconfigured", "scope": "no application response is inferred from TCP or process state"}}
	run := func(node, stage, kind string, payload any) map[string]any {
		s.step(ctx, id, stage, node, "running", "")
		v, e := s.command(ctx, id, node, stage, kind, payload)
		var data map[string]any
		if e != nil {
			data = map[string]any{"status": "unknown", "code": e.Error(), "at": time.Now().UTC()}
			s.step(ctx, id, stage, node, "failed", e.Error())
		} else {
			json.Unmarshal(v.Data, &data)
			s.step(ctx, id, stage, node, "succeeded", "")
		}
		data["source"] = node
		return data
	}
	processes := []any{}
	for node, instance := range rec.Instances {
		data := run(node, "process", "instance.status", map[string]string{"ID": instance})
		if active, ok := data["active"].(bool); ok {
			data["status"] = map[bool]string{true: "passed", false: "failed"}[active]
		}
		processes = append(processes, data)
	}
	out["process"] = processes
	transport := run(rec.Spec.Dialer, "transport", "diagnostic", nodeops.Diagnostic{Kind: "tcp", Endpoint: rec.Spec.TransportRemote})
	out["transport"] = transport
	if rec.Spec.Transport == "tls" || rec.Spec.Transport == "wss" || rec.Spec.Transport == "wssmux" {
		out["tls"] = run(rec.Spec.Dialer, "tls", "diagnostic", nodeops.Diagnostic{Kind: "tls", Endpoint: rec.Spec.TransportRemote, ServerName: rec.Spec.TLSName, CA: rec.Spec.Certificate})
	} else {
		out["tls"] = map[string]string{"status": "not_applicable"}
	}
	if p := rec.Spec.Application; p != nil && (p.Kind == "http" || p.Kind == "echo") {
		out["application"] = run(rec.Spec.Listener, "application", "diagnostic", nodeops.Diagnostic{Kind: p.Kind, Endpoint: p.Endpoint, Path: p.Path, Expected: p.Expected})
	}
	b, _ := json.Marshal(out)
	if q.Kind != "pending-plan" {
		s.DB.Exec(ctx, "UPDATE tunnels SET health=$1 WHERE id=$2", b, q.Tunnel)
	}
	s.DB.Exec(ctx, "INSERT INTO checks(node_id,target,kind,data)VALUES($1,$2,'tunnel',$3)", rec.Spec.Listener, q.Tunnel, b)
	s.phase(ctx, id, "succeeded", out, nil)
}
func (s *Server) pendingPlanCheck(w http.ResponseWriter, r *http.Request) {
	var input struct{ RequestKey string }
	if !decode(w, r, &input) {
		return
	}
	var cipher []byte
	var phase string
	if s.DB.QueryRow(r.Context(), "SELECT cipher,phase FROM operations WHERE id=$1 AND kind='plan'", r.PathValue("id")).Scan(&cipher, &phase) != nil || phase != "awaiting_confirmation" {
		badOperation(w, errors.New("no_active_plan_to_check"))
		return
	}
	var q JobPayload
	if s.openValue("operation:"+r.PathValue("id"), cipher, &q) != nil {
		badOperation(w, errors.New("operation_decryption_failed"))
		return
	}
	q.Kind = "pending-plan"
	id, e := s.newJob(r.Context(), input.RequestKey, "tunnel-check", q.Tunnel, "Check pending change", q)
	if e != nil {
		badOperation(w, e)
		return
	}
	write(w, map[string]string{"operation_id": id})
}
func (s *Server) tunnelHistory(w http.ResponseWriter, r *http.Request) {
	rows, e := s.DB.Query(r.Context(), "SELECT at,data FROM checks WHERE target=$1 AND kind='tunnel' ORDER BY at DESC LIMIT 100", r.PathValue("id"))
	if e != nil {
		badOperation(w, e)
		return
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var at time.Time
		var data []byte
		rows.Scan(&at, &data)
		out = append(out, map[string]any{"at": at, "data": json.RawMessage(data)})
	}
	write(w, out)
}
func (s *Server) evaluateAlerts(ctx context.Context) {
	settings := s.settingsCopy()
	offline := settings.AlertOfflineSeconds
	if offline == 0 {
		offline = 150
	}
	days := settings.AlertCertificateDays
	if days == 0 {
		days = 14
	}
	rows, e := s.DB.Query(ctx, "SELECT id,name,seen FROM nodes WHERE approved")
	if e != nil {
		return
	}
	type n struct {
		id, name string
		seen     *time.Time
	}
	nodes := []n{}
	for rows.Next() {
		var v n
		rows.Scan(&v.id, &v.name, &v.seen)
		nodes = append(nodes, v)
	}
	rows.Close()
	for _, v := range nodes {
		s.setAlert(ctx, "node-offline", v.id, "warning", "node_observation_stale", v.seen == nil || time.Since(*v.seen) > time.Duration(offline)*time.Second)
	}
	rows, e = s.DB.Query(ctx, "SELECT id,desired,health FROM tunnels")
	if e == nil {
		for rows.Next() {
			var id, desired string
			var raw []byte
			rows.Scan(&id, &desired, &raw)
			var h struct {
				At        time.Time `json:"at"`
				Transport struct {
					Status string `json:"status"`
				} `json:"transport"`
			}
			json.Unmarshal(raw, &h)
			s.setAlert(ctx, "transport", id, "warning", "transport_check_failed", desired == "running" && time.Since(h.At) < 4*time.Minute && h.Transport.Status == "failed")
		}
		rows.Close()
	}
	rows, e = s.DB.Query(ctx, "SELECT id,not_after FROM certificates")
	if e == nil {
		for rows.Next() {
			var id string
			var until time.Time
			rows.Scan(&id, &until)
			s.setAlert(ctx, "certificate", id, "warning", "certificate_expires_soon", time.Until(until) < time.Duration(days)*24*time.Hour)
		}
		rows.Close()
	}
}
func (s *Server) setAlert(ctx context.Context, rule, target, severity, code string, active bool) {
	if !active {
		s.DB.Exec(ctx, "UPDATE alerts SET active=false,updated=now() WHERE rule=$1 AND target=$2 AND active", rule, target)
		return
	}
	s.DB.Exec(ctx, "INSERT INTO alerts(rule,target,severity,code)VALUES($1,$2,$3,$4) ON CONFLICT(rule,target) WHERE active DO UPDATE SET updated=now(),code=EXCLUDED.code", rule, target, severity, code)
}
func (s *Server) alertList(w http.ResponseWriter, r *http.Request) {
	rows, e := s.DB.Query(r.Context(), "SELECT a.id,a.rule,COALESCE(n.name,t.name,c.name,a.target),a.target,a.severity,a.code,a.active,a.acknowledged,a.created,a.updated,a.suppressed_until FROM alerts a LEFT JOIN nodes n ON n.id=a.target LEFT JOIN tunnels t ON t.id=a.target LEFT JOIN certificates c ON c.id=a.target ORDER BY active DESC,a.updated DESC LIMIT 100")
	if e != nil {
		badOperation(w, e)
		return
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var id int64
		var rule, name, target, severity, code string
		var active, ack bool
		var created, updated time.Time
		var suppressed *time.Time
		rows.Scan(&id, &rule, &name, &target, &severity, &code, &active, &ack, &created, &updated, &suppressed)
		out = append(out, map[string]any{"id": id, "rule": rule, "name": name, "target": target, "severity": severity, "code": code, "active": active, "acknowledged": ack, "created": created, "updated": updated, "suppressed_until": suppressed})
	}
	write(w, out)
}
func (s *Server) alertUpdate(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Acknowledge   bool
		SuppressHours int
	}
	if !decode(w, r, &q) {
		return
	}
	if q.SuppressHours < 0 || q.SuppressHours > 168 {
		badOperation(w, errors.New("suppression_must_be_0_to_168_hours"))
		return
	}
	_, e := s.DB.Exec(r.Context(), "UPDATE alerts SET acknowledged=$1,suppressed_until=now()+$2*interval '1 hour' WHERE id=$3", q.Acknowledge, q.SuppressHours, r.PathValue("id"))
	if e != nil {
		badOperation(w, e)
		return
	}
	s.Audit(r.Context(), "alert-update", r.PathValue("id"), "acknowledgement-or-suppression")
	write(w, map[string]bool{"saved": true})
}

var _ = secure.Token
