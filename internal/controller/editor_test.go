package controller

import (
	"context"
	"encoding/json"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"strings"
	"testing"
)

func TestHumanChangesDescribeMappingsWithoutSecretValues(t *testing.T) {
	old := sharedSpec("client", "one", 24443)
	old.Application = &engine.Probe{Kind: "http", Endpoint: engine.Endpoint{Host: "entry.example.com", Port: 24443}, Expected: "synthetic-private-response"}
	next := old
	next.Routes = append([]engine.Route{}, old.Routes...)
	next.Routes[0].User.Port = 24444
	next.Routes[0].Backend = engine.Endpoint{Host: "192.0.2.20", Port: 443}
	next.Token = "synthetic-new-private-token"
	next.Transport = "wss"
	next.TransportBind.Port = 28101
	next.Application = &engine.Probe{Kind: "http", Endpoint: old.Application.Endpoint, Expected: "different-private-response"}
	changes := settingChanges(&old, next)
	encoded, _ := json.Marshal(changes)
	for _, secret := range []string{old.Token, next.Token, old.Application.Expected, next.Application.Expected} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("secret reached public change summary")
		}
	}
	for _, kind := range []string{"user_port", "backend", "token_changed", "transport", "transport_port", "probe"} {
		if !strings.Contains(string(encoded), `"kind":"`+kind+`"`) {
			t.Fatalf("missing change %s", kind)
		}
	}
}

func TestDraftNormalizationIsReadOnlyRevisionCheckedAndRedacted(t *testing.T) {
	s, srv, client := testServer(t)
	enrollMFA(t, srv, client)
	ctx := context.Background()
	spec := sharedSpec("client", "one", 24443)
	cipher, _ := s.sealValue("tunnel:edit", TunnelRecord{Spec: spec})
	s.DB.Exec(ctx, "INSERT INTO tunnels(id,name,cipher,managed)VALUES('edit','sample',$1,true)", cipher)
	status, value := request(t, client, srv.URL+"/api/tunnel-drafts/normalize", "POST", map[string]any{"Tunnel": "edit", "ExpectedRevision": 1, "Spec": engine.Public(spec)})
	if status != 200 {
		t.Fatal("draft normalization rejected")
	}
	b, _ := json.Marshal(value)
	if strings.Contains(string(b), spec.Token) || !strings.Contains(string(b), engine.Mask) {
		t.Fatal("draft returned secret")
	}
	var current []byte
	var jobs, commands int
	s.DB.QueryRow(ctx, "SELECT cipher FROM tunnels WHERE id='edit'").Scan(&current)
	s.DB.QueryRow(ctx, "SELECT count(*) FROM operations").Scan(&jobs)
	s.DB.QueryRow(ctx, "SELECT count(*) FROM commands").Scan(&commands)
	if string(current) != string(cipher) || jobs != 0 || commands != 0 {
		t.Fatal("draft preview mutated state or queued node commands")
	}
	status, _ = request(t, client, srv.URL+"/api/tunnel-drafts/normalize", "POST", map[string]any{"Tunnel": "edit", "ExpectedRevision": 2, "Spec": engine.Public(spec)})
	if status == 200 {
		t.Fatal("stale draft revision accepted")
	}
	s.DB.Exec(ctx, "UPDATE tunnels SET managed=false WHERE id='edit'")
	status, _ = request(t, client, srv.URL+"/api/tunnel-drafts/normalize", "POST", map[string]any{"Tunnel": "edit", "ExpectedRevision": 1, "Spec": engine.Public(spec)})
	if status == 200 {
		t.Fatal("unadopted draft accepted")
	}
}
