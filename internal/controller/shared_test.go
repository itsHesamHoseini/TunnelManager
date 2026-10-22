package controller

import (
	"context"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"strings"
	"testing"
)

func sharedSpec(dialer, route string, port int) engine.Spec {
	return engine.Spec{Engine: "backhaul", Version: "0.7.2", Transport: "tcp", Listener: "listener", Dialer: dialer, TransportBind: engine.Endpoint{Host: "0.0.0.0", Port: 28100}, TransportRemote: engine.Endpoint{Host: "listener.example.com", Port: 28100}, Token: "synthetic-shared-authentication", Routes: []engine.Route{{ID: route, Name: route, User: engine.Endpoint{Host: "0.0.0.0", Port: port}, Backend: engine.Endpoint{Host: "127.0.0.1", Port: 2096}, Protocol: "tcp"}}}
}
func TestSharedExpansionPreservesOtherClientRoutes(t *testing.T) {
	s, _, _ := testServer(t)
	ctx := context.Background()
	a := sharedSpec("client_a", "one", 24443)
	b := sharedSpec("client_b", "two", 24444)
	a.PeerOptions = map[string]map[string]any{"client": {"retry_interval": float64(3)}, "server": {"nodelay": true}}
	b.PeerOptions = map[string]map[string]any{"client": {"retry_interval": float64(7)}, "server": {"nodelay": true}}
	records := []TunnelUpdate{{ID: "a", Name: "A", Revision: 1, Record: TunnelRecord{Spec: a, Instances: map[string]string{"listener": "shared_server", "client_a": "client_a"}, Hashes: map[string]string{"listener": "same_hash", "client_a": "a_hash"}}}, {ID: "b", Name: "B", Revision: 1, Record: TunnelRecord{Spec: b, Instances: map[string]string{"listener": "shared_server", "client_b": "client_b"}, Hashes: map[string]string{"listener": "same_hash", "client_b": "b_hash"}}}}
	for _, v := range records {
		cipher, _ := s.sealValue("tunnel:"+v.ID, v.Record)
		s.DB.Exec(ctx, "INSERT INTO tunnels(id,name,cipher,managed)VALUES($1,$2,$3,true)", v.ID, v.Name, cipher)
	}
	a.Routes[0].User.Port = 24445
	q := JobPayload{Tunnel: "a", Name: "A", Spec: a, Instances: records[0].Record.Instances, Hashes: records[0].Record.Hashes, ExpectedRevision: 1}
	if e := s.expand(ctx, &q); e != nil {
		t.Fatal(e)
	}
	if len(q.Parts) != 3 || len(q.Updates) != 2 {
		t.Fatal("shared peer missing from impact")
	}
	for _, p := range q.Parts {
		if p.Role == "server" {
			if len(p.Spec.Routes) != 2 {
				t.Fatal("shared route was removed")
			}
			raw, e := engine.Render(p.Spec, "server")
			if e != nil {
				t.Fatal(e)
			}
			parsed, e := engine.ParseConfiguration(raw, "backhaul")
			if e != nil || len(parsed.Routes) != 2 {
				t.Fatal("shared server config lost a route")
			}
			m, _ := engine.Parse(raw)
			server, _ := m["server"].(map[string]any)
			if server["nodelay"] != true {
				t.Fatal("shared server option lost")
			}
		} else if p.Node == "client_b" && p.Spec.Routes[0].ID != "two" {
			t.Fatal("unrelated backend replaced")
		}
		if p.Node == "client_b" && p.Spec.PeerOptions["client"]["retry_interval"] != float64(7) {
			t.Fatal("another client's retry policy replaced")
		}
	}
	s.DB.Exec(ctx, "UPDATE tunnels SET managed=false WHERE id='b'")
	if s.expand(ctx, &q) == nil {
		t.Fatal("unadopted peer implicitly modified")
	}
}
func TestClientCommandsNeverReceiveListenerPrivateIdentity(t *testing.T) {
	spec := sharedSpec("client", "one", 24443)
	spec.Transport = "wss"
	spec.Certificate = "synthetic_certificate"
	spec.AllowUnverifiedTLS = true
	engine.GenerateSecrets(&spec)
	client := nodeSpec(ChangePart{Role: "client", Spec: spec})
	raw, e := engine.Render(client, "client")
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(raw, "tls_key") || strings.Contains(raw, "key.pem") || !strings.Contains(raw, "remote_addr") || !strings.Contains(raw, "token") {
		t.Fatal("connecting peer must receive shared authentication and endpoint, without listener private certificate files")
	}
}
