package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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
