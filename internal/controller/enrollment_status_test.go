package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEnrollmentStatusBindsOnlyConsumedIdentity(t *testing.T) {
	s, srv, c := testServer(t)
	enrollMFA(t, srv, c)
	ctx := context.Background()
	token, _ := s.CreateEnrollment(ctx, "Synthetic enrolled", "foreign", false)
	other, _ := s.CreateEnrollment(ctx, "Other", "iran", false)
	status, body := request(t, c, srv.URL+"/api/nodes/enrollment-status", "POST", map[string]string{"Token": token})
	if status != 200 || body["stage"] != "waiting" {
		t.Fatal("new enrollment not waiting")
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	status, enrolled := request(t, c, srv.URL+"/api/enroll", "POST", map[string]string{"token": token, "public_key": base64.RawURLEncoding.EncodeToString(pub)})
	if status != 200 {
		t.Fatal("actual identity enrollment failed")
	}
	id := enrolled["node_id"].(string)
	status, body = request(t, c, srv.URL+"/api/nodes/enrollment-status", "POST", map[string]string{"Token": token})
	node, _ := body["node"].(map[string]any)
	if status != 200 || body["stage"] != "identity_received" || node["id"] != id || node["fingerprint"] != secure.Fingerprint(pub) || node["approved"] != false {
		t.Fatal("status did not bind the full unapproved identity")
	}
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), token) {
		t.Fatal("token returned in progress")
	}
	status, body = request(t, c, srv.URL+"/api/nodes/enrollment-status", "POST", map[string]string{"Token": other})
	if status != 200 || body["node"] != nil || body["stage"] != "waiting" {
		t.Fatal("different enrollment disclosed linked identity")
	}
	status, _ = request(t, c, srv.URL+"/api/nodes/"+id+"/approve", "POST", map[string]string{"fingerprint": "wrong"})
	if status != 409 {
		t.Fatal("fingerprint guard bypassed")
	}
	status, _ = request(t, c, srv.URL+"/api/nodes/"+id+"/approve", "POST", map[string]string{"fingerprint": secure.Fingerprint(pub)})
	if status != 200 {
		t.Fatal("explicit matching identity not approved")
	}
	status, body = request(t, c, srv.URL+"/api/nodes/enrollment-status", "POST", map[string]string{"Token": token})
	if status != 200 || body["stage"] != "approved" {
		t.Fatalf("approval stage mismatch: http=%d stage=%v code=%v", status, body["stage"], body["code"])
	}
	s.DB.Exec(ctx, "UPDATE enrollment SET expires=now()-interval '1 second' WHERE hash=$1", secure.Hash(other))
	_, body = request(t, c, srv.URL+"/api/nodes/enrollment-status", "POST", map[string]string{"Token": other})
	if body["expired"] != true {
		t.Fatal("expiry not shown")
	}
	badOrigin, _ := http.NewRequest("POST", srv.URL+"/api/nodes/enrollment-status", bytes.NewReader([]byte(`{"Token":"`+token+`"}`)))
	badOrigin.Header.Set("Origin", "https://untrusted.example.test")
	badOrigin.Header.Set("Content-Type", "application/json")
	response, e := c.Do(badOrigin)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("read-only status bypassed origin guard")
	}
	// Private status route cannot be read without an authenticated session.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/nodes/enrollment-status", nil)
	s.Handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("enrollment progress route is public")
	}
}
