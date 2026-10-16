package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"github.com/itsHesamHoseini/TunnelManager/internal/nodeops"
	"sync"
	"testing"
	"time"
)

func TestDurableJobIdempotencyAndEncryption(t *testing.T) {
	s, _, _ := testServer(t)
	ctx := context.Background()
	p := JobPayload{Node: "synthetic", Kind: "engine.install", Payload: json.RawMessage(`{"token":"synthetic-command-secret"}`)}
	id, e := s.newJob(ctx, "request1", "node", "node1", "Install", p)
	if e != nil {
		t.Fatal(e)
	}
	duplicate, e := s.newJob(ctx, "request1", "node", "node1", "Install", p)
	if e != nil || duplicate != id {
		t.Fatal("request duplicated")
	}
	p.Kind = "unexpected"
	if _, e = s.newJob(ctx, "request1", "node", "node1", "Install", p); e == nil {
		t.Fatal("same key accepted changed input")
	}
	var cipher []byte
	s.DB.QueryRow(ctx, "SELECT cipher FROM operations WHERE id=$1", id).Scan(&cipher)
	if bytes.Contains(cipher, []byte("synthetic-command-secret")) {
		t.Fatal("secret stored plaintext")
	}
	var out JobPayload
	if s.openValue("different-purpose", cipher, &out) == nil {
		t.Fatal("cipher purpose substitution accepted")
	}
}
func TestPortReservationsSerializeConflictingPlans(t *testing.T) {
	s, _, _ := testServer(t)
	ctx := context.Background()
	s.DB.Exec(ctx, "INSERT INTO nodes(id,name,role,pubkey,approved,protocol)VALUES('n1','Synthetic','iran',$1,true,2)", make([]byte, 32))
	spec := engine.Spec{Listener: "n1", TransportBind: engine.Endpoint{Host: "0.0.0.0", Port: 28100}, Routes: []engine.Route{{User: engine.Endpoint{Host: "0.0.0.0", Port: 24443}, Protocol: "tcp"}}}
	ids := []string{}
	for _, key := range []string{"plan1", "plan2"} {
		id, e := s.newJob(ctx, key, "plan", "t", "Plan", JobPayload{})
		if e != nil {
			t.Fatal(e)
		}
		ids = append(ids, id)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, id := range ids {
		wg.Add(1)
		go func(id string) { defer wg.Done(); results <- s.reserve(ctx, id, JobPayload{Spec: spec}) }(id)
	}
	wg.Wait()
	close(results)
	passed, blocked := 0, 0
	for e := range results {
		if e == nil {
			passed++
		} else {
			blocked++
		}
	}
	if passed != 1 || blocked != 1 {
		t.Fatal("concurrent plans did not conflict")
	}
}
func TestPairingPreservesDirectionAndSharedRoutes(t *testing.T) {
	a := nodeops.Discovered{Instance: nodeops.Instance{Engine: "rathole", Version: "0.5.0", Role: "server"}, Parsed: engine.Parsed{Transport: "noise", Bind: "0.0.0.0:28100", Routes: []engine.Route{{ID: "one", User: engine.Endpoint{Host: "0.0.0.0", Port: 443}, Protocol: "tcp"}, {ID: "other", User: engine.Endpoint{Host: "0.0.0.0", Port: 8443}, Protocol: "tcp"}}}}
	b := nodeops.Discovered{Instance: nodeops.Instance{Engine: "rathole", Role: "client"}, Parsed: engine.Parsed{Transport: "noise", Remote: "listener.example.com:28100", Routes: []engine.Route{{ID: "one", Backend: engine.Endpoint{Host: "127.0.0.1", Port: 2096}, Protocol: "tcp"}}}}
	spec, e := pairedSpec("iran", "foreign", a, b)
	if e != nil {
		t.Fatal(e)
	}
	if len(spec.Routes) != 1 || spec.Listener != "iran" || spec.Dialer != "foreign" || spec.Routes[0].Backend.Port != 2096 {
		t.Fatal("pairing swapped user or control direction")
	}
}
func TestPublicResultDoesNotExposeNestedSecrets(t *testing.T) {
	raw := json.RawMessage(`{"private_configuration":"hidden","nested":{"token":"hidden","key":"hidden","configuration":"[redacted]"},"at":"2026-10-16"}`)
	b, _ := json.Marshal(publicData(raw))
	if bytes.Contains(b, []byte("hidden")) {
		t.Fatal("operation result secret escaped redaction")
	}
	_ = time.Second
}
