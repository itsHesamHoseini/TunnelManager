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
	a := nodeops.Discovered{Instance: nodeops.Instance{Engine: "backhaul", Version: "0.7.2", Role: "server"}, Parsed: engine.Parsed{Transport: "tcp", Bind: "0.0.0.0:28100", Routes: []engine.Route{{ID: "one", User: engine.Endpoint{Host: "0.0.0.0", Port: 443}, Backend: engine.Endpoint{Host: "127.0.0.1", Port: 2096}, Protocol: "tcp"}, {ID: "other", User: engine.Endpoint{Host: "0.0.0.0", Port: 8443}, Protocol: "tcp"}}}}
	b := nodeops.Discovered{Instance: nodeops.Instance{Engine: "backhaul", Role: "client"}, Parsed: engine.Parsed{Transport: "tcp", Remote: "listener.example.com:28100", Routes: []engine.Route{{ID: "one", Backend: engine.Endpoint{Host: "127.0.0.1", Port: 2096}, Protocol: "tcp"}}}}
	spec, e := pairedSpec("iran", "foreign", a, b)
	if e != nil {
		t.Fatal(e)
	}
	if len(spec.Routes) != 2 || spec.Listener != "iran" || spec.Dialer != "foreign" || spec.Routes[0].Backend.Port != 2096 {
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

func TestManualReimportRefreshesOnlyObservationMetadata(t *testing.T) {
	s, _, _ := testServer(t)
	ctx := context.Background()
	spec := sharedSpec("dialer", "one", 24443)
	spec.PeerOptions = map[string]map[string]any{"server": nil, "client": nil}
	if e := engine.Validate(spec); e != nil {
		t.Fatal("empty imported option maps rejected: ", e)
	}
	a := nodeops.Discovered{Instance: nodeops.Instance{ID: "server", Hash: "first"}}
	b := nodeops.Discovered{Instance: nodeops.Instance{ID: "client", Hash: "client_first"}}
	id, e := s.storeImport(ctx, "Imported", spec, a, b, true)
	if e != nil {
		t.Fatal(e)
	}
	s.DB.Exec(ctx, "UPDATE tunnels SET managed=true WHERE id=$1", id)
	a.Hash = "manual_current"
	spec.Routes[0].User.Port = 24445
	if _, e = s.storeImport(ctx, "Changed", spec, a, b, true); e == nil {
		t.Fatal("manual import overwrote managed record")
	}
	s.DB.Exec(ctx, "UPDATE tunnels SET managed=false WHERE id=$1", id)
	refreshed, e := s.storeImport(ctx, "Changed", spec, a, b, true)
	if e != nil || refreshed != id {
		t.Fatal("observation identity lost")
	}
	record, revision, managed, e := s.readTunnel(ctx, id)
	if e != nil || revision != 2 || managed || record.Spec.Routes[0].User.Port != 24445 || record.Hashes[spec.Listener] != "manual_current" {
		t.Fatal("fresh observed config not imported")
	}
}
