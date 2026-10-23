package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTunnelHealthUsesAuthoritativeNodeAvailability(t *testing.T) {
	s, srv, client := testServer(t)
	ctx := context.Background()
	conn := fixtureNode(t, s, srv, client, ctx)
	defer conn.CloseNow()
	record := TunnelRecord{Instances: map[string]string{"live-fixture": "sample-instance"}}
	raw := []byte(`{"at":"2026-10-23T00:00:00Z","transport":{"status":"passed"}}`)
	for _, tc := range []struct {
		name      string
		approved  bool
		age       time.Duration
		telemetry string
		stale     bool
	}{
		{"fresh", true, 0, `{"cpu_percent":12}`, false},
		{"future", true, -time.Hour, `{"cpu_percent":12}`, true},
		{"no telemetry", true, 0, `{}`, true},
		{"approval revoked", false, 0, `{"cpu_percent":12}`, true},
		{"old", true, 91 * time.Second, `{"cpu_percent":12}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.DB.Exec(ctx, "UPDATE nodes SET approved=$1,seen=$2,telemetry=$3 WHERE id='live-fixture'", tc.approved, time.Now().Add(-tc.age), []byte(tc.telemetry)); err != nil {
				t.Fatal(err)
			}
			health := s.currentHealth(ctx, raw, record).(map[string]any)
			stale, _ := health["stale"].(bool)
			if stale != tc.stale {
				t.Fatalf("node/tunnel availability disagrees: stale=%v want=%v", stale, tc.stale)
			}
		})
	}
}

func TestObservationTruth(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name                string
		approved, connected bool
		age                 time.Duration
		data, reason        string
		online, fresh       bool
	}{
		{"fresh", true, true, 0, `{"cpu_percent":12}`, "fresh_observation", true, true},
		{"edge", true, true, 90 * time.Second, `{"cpu_percent":12}`, "fresh_observation", true, true},
		{"old", true, true, 91 * time.Second, `{"cpu_percent":12}`, "observation_stale", false, false},
		{"disconnected but recent", true, false, time.Second, `{"cpu_percent":95}`, "agent_disconnected", false, true},
		{"missing", true, true, 0, `{}`, "no_observations", false, false},
		{"pending", false, true, 0, `{"cpu_percent":12}`, "approval_pending", false, true},
		{"future", true, true, -time.Second, `{"cpu_percent":12}`, "observation_stale", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := now.Add(-tc.age)
			online, fresh, reason := observationState(tc.approved, tc.connected, &seen, []byte(tc.data), now)
			if online != tc.online || fresh != tc.fresh || reason != tc.reason {
				t.Fatalf("got online=%v fresh=%v reason=%s", online, fresh, reason)
			}
		})
	}
	if online, _, reason := observationState(true, true, nil, []byte(`{"cpu_percent":12}`), now); online || reason != "no_observations" {
		t.Fatal("nil sample accepted")
	}
}

func TestRequestIDErrorContract(t *testing.T) {
	// Use the real handler middleware without PostgreSQL for its invalid-path
	// early error. A supplied ID must never be reflected as trusted metadata.
	s := &Server{}
	r := httptest.NewRequest(http.MethodGet, "/"+strings.Repeat("x", 513), nil)
	r.Header.Set("X-Request-ID", "untrusted-client-value")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var body map[string]string
	if e := json.Unmarshal(w.Body.Bytes(), &body); e != nil {
		t.Fatal(e)
	}
	id := w.Header().Get("X-Request-ID")
	if w.Code != 400 || id == "" || id == "untrusted-client-value" || body["request_id"] != id {
		t.Fatalf("error/header ID contract failed, status=%d", w.Code)
	}
}
