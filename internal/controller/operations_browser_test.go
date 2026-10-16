package controller

import (
	"context"
	"encoding/json"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"github.com/itsHesamHoseini/TunnelManager/internal/nodeops"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestOperationalPagesInBrowser(t *testing.T) {
	if os.Getenv("TUNNELMANAGER_BROWSER_TESTS") != "1" {
		t.Skip("browser opt-in")
	}
	s, srv, _ := testServer(t)
	ctx := context.Background()
	for _, node := range []string{"listener", "dialer"} {
		s.DB.Exec(ctx, "INSERT INTO nodes(id,name,role,pubkey,approved,protocol,seen)VALUES($1,$2,'foreign',$3,true,2,now())", node, "Synthetic "+node, make([]byte, 32))
	}
	for i, status := range []string{"passed", "failed", "unknown", "stale"} {
		id := "synthetic_" + status
		spec := engine.Spec{Engine: "rathole", Version: "0.5.0", Transport: "noise", Listener: "listener", Dialer: "dialer", TransportBind: engine.Endpoint{Host: "0.0.0.0", Port: 28100 + i}, TransportRemote: engine.Endpoint{Host: "192.0.2.10", Port: 28100 + i}, Routes: []engine.Route{{ID: "route1", Name: "Synthetic route", User: engine.Endpoint{Host: "0.0.0.0", Port: 24443 + i}, Backend: engine.Endpoint{Host: "127.0.0.1", Port: 2096}, Protocol: "tcp"}}}
		engine.GenerateSecrets(&spec)
		rec := TunnelRecord{Spec: spec, Instances: map[string]string{"listener": "synthetic_server", "dialer": "synthetic_client"}, Hashes: map[string]string{"listener": "hash1", "dialer": "hash2"}}
		cipher, _ := s.sealValue("tunnel:"+id, rec)
		at := time.Now()
		if status == "stale" {
			at = at.Add(-10 * time.Minute)
			status = "passed"
		}
		health, _ := json.Marshal(map[string]any{"at": at, "process": []map[string]any{{"status": status}, {"status": status}}, "transport": map[string]any{"status": status, "source": "dialer"}, "application": map[string]any{"status": "unconfigured"}})
		s.DB.Exec(ctx, "INSERT INTO tunnels(id,name,cipher,managed,health)VALUES($1,$2,$3,true,$4)", id, "Synthetic "+id, cipher, health)
	}
	inventory, _ := json.Marshal(map[string]any{"instances": []nodeops.Discovered{{Instance: nodeops.Instance{ID: "synthetic_server", Name: "Synthetic shared service", Unit: "rathole-synthetic.service", Engine: "rathole", Version: "0.5.0", Role: "server", Managed: true}, Parsed: engine.Parsed{Role: "server", Transport: "noise", Bind: "0.0.0.0:28100"}, Configuration: "[server]\nbind_addr='0.0.0.0:28100'\ndefault_token='[redacted]'\n", Active: "active"}}})
	s.DB.Exec(ctx, "UPDATE nodes SET inventory=$1,inventory_at=now() WHERE id='listener'", inventory)
	diagnostic, _ := s.newJob(ctx, "fixture_diagnostic", "node", "listener", "Fixture diagnostic failed", JobPayload{Node: "listener", Kind: "diagnostic", Payload: json.RawMessage(`{"kind":"tcp","endpoint":{"host":"192.0.2.10","port":443}}`)})
	result, _ := json.Marshal(map[string]any{"status": "failed", "kind": "tcp", "target": "192.0.2.10:443", "at": time.Now(), "code": "connection_or_protocol_check_failed"})
	s.DB.Exec(ctx, "UPDATE operations SET phase='succeeded',result=$1 WHERE id=$2", result, diagnostic)
	s.newJob(ctx, "fixture_queued", "node", "listener", "Fixture queued operation", JobPayload{Node: "listener", Kind: "inventory"})
	cmd := exec.Command("node", "web/tests/operations.mjs")
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), "TUNNELMANAGER_TEST_URL="+srv.URL)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("operational browser: %v\n%s", e, out)
	}
}
