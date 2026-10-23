package controller

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/coder/websocket"
	"github.com/itsHesamHoseini/TunnelManager/internal/protocol"
	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
	"net/http"
	"strings"
	"time"
)

func (s *Server) CreateEnrollment(ctx context.Context, name, role string, auto bool) (string, error) {
	if name == "" || len(name) > 80 {
		return "", errors.New("name required (at most 80 characters)")
	}
	if role != "iran" && role != "foreign" {
		role = "foreign"
	}
	token := secure.Token(32)
	_, e := s.DB.Exec(ctx, "INSERT INTO enrollment(hash,expires,name,role,auto_approve)VALUES($1,now()+interval '10 minutes',$2,$3,$4)", secure.Hash(token), name, role, auto)
	return token, e
}
func (s *Server) nodeToken(w http.ResponseWriter, r *http.Request) {
	var q struct{ Name, Role string }
	if !decode(w, r, &q) {
		return
	}
	token, e := s.CreateEnrollment(r.Context(), q.Name, q.Role, false)
	if e != nil {
		fail(w, 400, "invalid_input", e.Error(), "نام سرور را بررسی کنید.")
		return
	}
	s.Audit(r.Context(), "enrollment-token", q.Name, "created")
	bootstrap, bootstrapError := s.bootstrapCommand()
	write(w, map[string]any{"token": token, "controller": s.Config.Origin, "expires_seconds": 600, "command": "tunnelmanager setup --mode node --controller " + shellLiteral(s.Config.Origin) + " --token-stdin", "bootstrap_command": bootstrap, "bootstrap_available": bootstrapError == nil, "note": "The one-time token is read from a hidden prompt, never a shell argument."})
}
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	if s.limited(w, r, "enroll:"+s.ip(r), .05, 5) {
		return
	}
	var q struct {
		Token     string `json:"token"`
		PublicKey string `json:"public_key"`
	}
	if !decode(w, r, &q) {
		return
	}
	pub, e := base64.RawURLEncoding.DecodeString(q.PublicKey)
	if e != nil || len(pub) != ed25519.PublicKeySize {
		fail(w, 400, "invalid_key", "Invalid node identity.", "هویت سرور معتبر نیست.")
		return
	}
	ctx := r.Context()
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return
	}
	defer tx.Rollback(ctx)
	var name, role string
	var auto bool
	e = tx.QueryRow(ctx, "UPDATE enrollment SET consumed=true WHERE hash=$1 AND expires>now() AND NOT consumed RETURNING name,role,auto_approve", secure.Hash(q.Token)).Scan(&name, &role, &auto)
	if e != nil {
		fail(w, 401, "invalid_enrollment", "Token expired or already used. Generate a new one.", "توکن منقضی یا استفاده شده است؛ توکن تازه بسازید.")
		return
	}
	id := secure.Token(12)
	_, e = tx.Exec(ctx, "INSERT INTO nodes(id,name,role,pubkey,approved)VALUES($1,$2,$3,$4,$5)", id, name, role, pub, auto)
	if e == nil {
		_, e = tx.Exec(ctx, "UPDATE enrollment SET node_id=$1 WHERE hash=$2", id, secure.Hash(q.Token))
	}
	if e != nil || tx.Commit(ctx) != nil {
		fail(w, 503, "busy", "Try again.", "دوباره تلاش کنید.")
		return
	}
	s.Audit(ctx, "node-enroll", id, "pending")
	write(w, map[string]any{"node_id": id, "approved": auto, "protocol": protocol.Version})
}
func (s *Server) enrollmentStatus(w http.ResponseWriter, r *http.Request) {
	var q struct{ Token string }
	if !decode(w, r, &q) {
		return
	}
	if len(q.Token) < 20 || len(q.Token) > 200 {
		fail(w, 400, "invalid_enrollment", "Generate a new enrollment.", "ثبت تازه بسازید.")
		return
	}
	var expires time.Time
	var consumed bool
	var node *string
	if e := s.DB.QueryRow(r.Context(), "SELECT expires,consumed,node_id FROM enrollment WHERE hash=$1", secure.Hash(q.Token)).Scan(&expires, &consumed, &node); e != nil {
		fail(w, 404, "invalid_enrollment", "Generate a new enrollment.", "ثبت تازه بسازید.")
		return
	}
	result := map[string]any{"expires": expires, "expired": time.Now().After(expires), "consumed": consumed, "stage": "waiting"}
	if node != nil {
		var name string
		var pub []byte
		var approved bool
		var seen *time.Time
		var data []byte
		if e := s.DB.QueryRow(r.Context(), "SELECT name,pubkey,approved,seen,COALESCE(telemetry,'{}') FROM nodes WHERE id=$1", *node).Scan(&name, &pub, &approved, &seen, &data); e != nil {
			fail(w, 409, "enrolled_node_missing", "This enrolled server is no longer listed.", "سرور ثبت‌شده دیگر در فهرست نیست؛ ثبت تازه بسازید.")
			return
		}
		result["node"] = map[string]any{"id": *node, "name": name, "fingerprint": secure.Fingerprint(pub), "approved": approved, "seen": seen}
		result["stage"] = "identity_received"
		if approved {
			result["stage"] = "approved"
			if online, _, _ := observationState(true, s.isConnected(*node), seen, data, time.Now()); online {
				result["stage"] = "observing"
			}
		}
	}
	write(w, result)
}
func (s *Server) nodes(w http.ResponseWriter, r *http.Request) {
	rows, e := s.DB.Query(r.Context(), "SELECT id,name,role,approved,seen,reconnects,COALESCE(telemetry,'{}'),metadata,pubkey,revision FROM nodes ORDER BY name")
	if e != nil {
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, n, role string
		var a bool
		var seen *time.Time
		var reconnects int
		var revision int64
		var data, meta, pub []byte
		rows.Scan(&id, &n, &role, &a, &seen, &reconnects, &data, &meta, &pub, &revision)
		connected := s.isConnected(id)
		online, fresh, reason := observationState(a, connected, seen, data, time.Now())
		items = append(items, map[string]any{"id": id, "name": n, "role": role, "approved": a, "connected": connected, "online": online, "observation_reason": reason, "seen": seen, "reconnects": reconnects, "telemetry": json.RawMessage(data), "metadata": json.RawMessage(meta), "fingerprint": secure.Fingerprint(pub), "revision": revision, "fresh": fresh})
	}
	write(w, items)
}
func (s *Server) nodeDetail(w http.ResponseWriter, r *http.Request) {
	var id, name, role string
	var approved bool
	var seen *time.Time
	var data, meta, pub []byte
	var reconnects int
	var revision int64
	e := s.DB.QueryRow(r.Context(), "SELECT id,name,role,approved,seen,reconnects,COALESCE(telemetry,'{}'),metadata,pubkey,revision FROM nodes WHERE id=$1", r.PathValue("id")).Scan(&id, &name, &role, &approved, &seen, &reconnects, &data, &meta, &pub, &revision)
	if e != nil {
		fail(w, 404, "node_missing", "Node not found.", "سرور پیدا نشد.")
		return
	}
	connected := s.isConnected(id)
	online, fresh, reason := observationState(approved, connected, seen, data, time.Now())
	write(w, map[string]any{"id": id, "name": name, "role": role, "approved": approved, "connected": connected, "online": online, "observation_reason": reason, "seen": seen, "telemetry": json.RawMessage(data), "metadata": json.RawMessage(meta), "reconnects": reconnects, "fingerprint": secure.Fingerprint(pub), "revision": revision, "usage": s.usage(r.Context(), id), "fresh": fresh})
}
func (s *Server) isConnected(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connected[id] != nil
}
func (s *Server) nodeApprove(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Fingerprint string `json:"fingerprint"`
	}
	if !decode(w, r, &q) {
		return
	}
	var pub []byte
	if e := s.DB.QueryRow(r.Context(), "SELECT pubkey FROM nodes WHERE id=$1", r.PathValue("id")).Scan(&pub); e != nil || q.Fingerprint != secure.Fingerprint(pub) {
		fail(w, 409, "identity_mismatch", "Compare the installer fingerprint before approval.", "اثر انگشت نمایش‌داده‌شده در نصب‌کننده را پیش از تأیید مقایسه کنید.")
		return
	}
	tag, e := s.DB.Exec(r.Context(), "UPDATE nodes SET approved=true WHERE id=$1 AND NOT approved", r.PathValue("id"))
	if e != nil || tag.RowsAffected() != 1 {
		fail(w, 409, "already_approved", "Already approved or missing.", "سرور قبلاً تأیید شده یا وجود ندارد.")
		return
	}
	s.Audit(r.Context(), "node-approve", r.PathValue("id"), "approved")
	write(w, map[string]bool{"ok": true})
}
func (s *Server) nodeUpdate(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Name             string   `json:"name"`
		Role             string   `json:"role"`
		Tags             []string `json:"tags"`
		Notes            string   `json:"notes"`
		Provider         string   `json:"provider"`
		Country          string   `json:"country"`
		Expiry           string   `json:"expiry"`
		TrafficCap       uint64   `json:"traffic_cap"`
		ExpectedRevision int64    `json:"expected_revision"`
	}
	if !decode(w, r, &q) {
		return
	}
	if q.Name == "" || len(q.Name) > 80 || (q.Role != "iran" && q.Role != "foreign") || len(q.Notes) > 2000 || len(q.Tags) > 20 {
		fail(w, 400, "invalid_input", "Check the server details.", "اطلاعات سرور را بررسی کنید.")
		return
	}
	q.Country = strings.ToUpper(q.Country)
	if q.Country != "" && (len(q.Country) != 2 || q.Country[0] < 'A' || q.Country[0] > 'Z' || q.Country[1] < 'A' || q.Country[1] > 'Z') {
		fail(w, 400, "invalid_country", "Use a two-letter country code or leave empty.", "کد دوحرفی کشور را وارد کنید یا خالی بگذارید.")
		return
	}
	if q.Expiry != "" {
		if _, e := time.Parse("2006-01-02", q.Expiry); e != nil {
			fail(w, 400, "invalid_expiry", "Use YYYY-MM-DD.", "تاریخ میلادی معتبر وارد کنید.")
			return
		}
	}
	meta, _ := json.Marshal(q)
	tag, e := s.DB.Exec(r.Context(), "UPDATE nodes SET name=$1,role=$2,metadata=$3,revision=revision+1 WHERE id=$4 AND revision=$5", q.Name, q.Role, meta, r.PathValue("id"), q.ExpectedRevision)
	if e != nil || tag.RowsAffected() != 1 {
		fail(w, 409, "server_changed", "Server details changed. Refresh and compare before saving; your draft is preserved.", "اطلاعات سرور تغییر کرده است؛ پیش‌نویس را نگه دارید و پس از تازه‌سازی مقایسه کنید.")
		return
	}
	s.Audit(r.Context(), "node-edit", r.PathValue("id"), "success")
	write(w, map[string]bool{"ok": true})
}
func (s *Server) nodeDelete(w http.ResponseWriter, r *http.Request) {
	var q struct{ Confirm bool }
	if !decode(w, r, &q) || !q.Confirm {
		return
	}
	id := r.PathValue("id")
	s.DB.Exec(r.Context(), "DELETE FROM nodes WHERE id=$1", id)
	s.mu.Lock()
	if c := s.connected[id]; c != nil {
		c.CloseNow()
		delete(s.connected, id)
	}
	s.mu.Unlock()
	s.Audit(r.Context(), "node-remove", id, "identity revoked; host services preserved")
	write(w, map[string]bool{"ok": true})
}
func (s *Server) nodeHistory(w http.ResponseWriter, r *http.Request) {
	if s.aggregateHistory(w, r) {
		return
	}
	rows, e := s.DB.Query(r.Context(), "SELECT at,data FROM measurements WHERE node_id=$1 ORDER BY at DESC LIMIT 240", r.PathValue("id"))
	if e != nil {
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var at time.Time
		var data []byte
		rows.Scan(&at, &data)
		items = append(items, map[string]any{"at": at, "data": json.RawMessage(data)})
	}
	write(w, items)
}
func (s *Server) agentConnection(w http.ResponseWriter, r *http.Request) {
	handshakeHeld := true
	select {
	case s.agentSlots <- struct{}{}:
		defer func() {
			if handshakeHeld {
				<-s.agentSlots
			}
		}()
	default:
		w.Header().Set("Retry-After", "10")
		fail(w, 429, "agent_capacity", "Retry enrollment/connection in ten seconds.", "۱۰ ثانیه بعد دوباره تلاش کنید.")
		return
	}
	if s.limited(w, r, "agent-connect:"+s.ip(r), .1, 10) {
		return
	}
	c, e := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{}})
	if e != nil {
		return
	}
	defer c.CloseNow()
	c.SetReadLimit(protocol.MaxFrame)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	hello := protocol.Hello{Nonce: secure.Token(32), Expires: time.Now().Add(10 * time.Second)}
	b, _ := json.Marshal(hello)
	if c.Write(ctx, websocket.MessageText, b) != nil {
		return
	}
	_, b, e = c.Read(ctx)
	if e != nil {
		return
	}
	var auth protocol.Authentication
	if json.Unmarshal(b, &auth) != nil {
		return
	}
	if auth.Protocol < 0 || auth.Protocol > 2 {
		return
	}
	var pub []byte
	var approved bool
	e = s.DB.QueryRow(ctx, "SELECT pubkey,approved FROM nodes WHERE id=$1", auth.NodeID).Scan(&pub, &approved)
	sig, err := base64.RawURLEncoding.DecodeString(auth.Signature)
	message := auth.NodeID + "\n" + hello.Nonce + "\n" + hello.Expires.UTC().Format(time.RFC3339Nano)
	if e != nil || err != nil || !approved || len(pub) != 32 || !ed25519.Verify(pub, []byte(message), sig) {
		c.Close(websocket.StatusPolicyViolation, "pending approval or invalid identity")
		return
	}
	<-s.agentSlots
	handshakeHeld = false
	s.mu.Lock()
	if _, exists := s.connected[auth.NodeID]; exists || len(s.connected) >= 100 {
		s.mu.Unlock()
		c.Close(websocket.StatusPolicyViolation, "connection already active or capacity reached")
		return
	}
	s.connected[auth.NodeID] = c
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.connected, auth.NodeID); s.mu.Unlock() }()
	s.DB.Exec(r.Context(), "UPDATE nodes SET reconnects=reconnects+1,protocol=$2 WHERE id=$1", auth.NodeID, max(1, auth.Protocol))
	s.Audit(r.Context(), "node-connect", auth.NodeID, "authenticated")
	last := time.Time{}
	lastFrame := time.Time{}
	for {
		readCtx, stop := context.WithTimeout(r.Context(), 60*time.Second)
		_, b, e = c.Read(readCtx)
		stop()
		if e != nil {
			return
		}
		if time.Since(lastFrame) < 500*time.Millisecond {
			c.Close(websocket.StatusPolicyViolation, "frame rate exceeded")
			return
		}
		lastFrame = time.Now()
		if auth.Protocol < 2 && time.Since(last) < 10*time.Second {
			c.Close(websocket.StatusPolicyViolation, "telemetry rate exceeded")
			return
		}
		var frame protocol.Frame
		if json.Unmarshal(b, &frame) != nil || (frame.Version != 1 && frame.Version != 2) {
			c.Close(websocket.StatusPolicyViolation, "unknown typed action")
			return
		}
		if frame.Version == 2 {
			if auth.Protocol < 2 || s.acceptResults(r.Context(), auth.NodeID, frame.Results) != nil {
				return
			}
			if frame.Type == "poll" {
				ack, _ := json.Marshal(protocol.Ack{Type: "accepted", Command: s.deliverCommand(r.Context(), auth.NodeID)})
				writeCtx, done := context.WithTimeout(r.Context(), 5*time.Second)
				e = c.Write(writeCtx, websocket.MessageText, ack)
				done()
				if e != nil {
					return
				}
				continue
			}
		}
		if frame.Type != "telemetry" || frame.Data == nil {
			return
		}
		if time.Since(last) < 10*time.Second {
			c.Close(websocket.StatusPolicyViolation, "telemetry rate exceeded")
			return
		}
		data := frame.Data
		if data.At.Before(time.Now().Add(-2*time.Minute)) || data.At.After(time.Now().Add(time.Minute)) || len(data.Processes) > 150 || len(data.Listeners) > 300 || len(data.Services) > 100 || len(data.Networks) > 100 {
			c.Close(websocket.StatusPolicyViolation, "invalid measurement")
			return
		}
		data.OS = short(data.OS, 100)
		data.Scope = "host; CPU normalized across cores; network per interface; not tunnel health"
		for i := range data.Processes {
			data.Processes[i].Name = strings.Map(func(r rune) rune {
				if r < 32 {
					return -1
				}
				return r
			}, short(data.Processes[i].Name, 80))
		}
		b, _ = json.Marshal(data)
		historyData, _ := json.Marshal(map[string]any{"at": data.At, "cpu_percent": data.CPU, "ram_used": data.RAMUsed, "ram_total": data.RAMTotal, "disk_total": data.DiskTotal, "disk_free": data.DiskFree, "networks": data.Networks, "process_count": len(data.Processes), "listener_count": len(data.Listeners), "scope": "host summary; process/listener lists are only current snapshots"})
		tx, e := s.DB.Begin(r.Context())
		if e != nil {
			return
		}
		var previous []byte
		if e = tx.QueryRow(r.Context(), "SELECT COALESCE(telemetry,'{}') FROM nodes WHERE id=$1 FOR UPDATE", auth.NodeID).Scan(&previous); e != nil {
			tx.Rollback(r.Context())
			return
		}
		if e = recordUsage(r.Context(), tx, auth.NodeID, previous, data); e != nil {
			tx.Rollback(r.Context())
			return
		}
		tag, e := tx.Exec(r.Context(), "UPDATE nodes SET seen=now(),telemetry=$1 WHERE id=$2 AND approved", b, auth.NodeID)
		if e == nil && tag.RowsAffected() == 1 {
			_, e = tx.Exec(r.Context(), "INSERT INTO measurements(node_id,data)VALUES($1,$2)", auth.NodeID, historyData)
		} else {
			tx.Rollback(r.Context())
			return
		}
		if e != nil || tx.Commit(r.Context()) != nil {
			tx.Rollback(r.Context())
			return
		}
		last = time.Now()
		var response any = map[string]string{"type": "accepted"}
		if frame.Version == 2 {
			response = protocol.Ack{Type: "accepted", Command: s.deliverCommand(r.Context(), auth.NodeID)}
		}
		ack, _ := json.Marshal(response)
		writeCtx, done := context.WithTimeout(r.Context(), 5*time.Second)
		e = c.Write(writeCtx, websocket.MessageText, ack)
		done()
		if e != nil {
			return
		}
	}
}
func (s *Server) Maintenance(ctx context.Context) {
	s.retain(ctx)
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.retain(ctx)
			s.DB.Exec(ctx, "DELETE FROM sessions WHERE expires<now()")
			s.DB.Exec(ctx, "DELETE FROM auth_failures WHERE updated<now()-interval '1 day'")
			s.DB.Exec(ctx, "DELETE FROM challenges WHERE expires<now()")
			s.DB.Exec(ctx, "DELETE FROM enrollment WHERE expires<now()")
		}
	}
}
